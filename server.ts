import crypto from 'crypto';
import express from 'express';
import fs from 'fs';
import http from 'http';
import net from 'net';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import WebSocket, { WebSocketServer } from 'ws';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MCP_ROOT = path.resolve(__dirname, 'enterprise-switch-mcp');

interface RegisteredDevice {
  hostname: string;
  mgmtIp: string;
  sshPort: number;
  vendor: 'cisco' | 'aruba';
  model: string;
  siteCode: string;
  isStacked: boolean;
  sshUsername: string;
  vaultSecretPath: string;
  status: string;
  lastCheckedAt: string;
  lastLatencyMs: number | null;
  lastError: string | null;
}

export interface LiveSSHSession {
  session_id: string;
  hostname: string;
  mgmt_ip: string;
  ssh_port: number;
  vendor: string;
  model: string;
  status: 'connecting' | 'connected' | 'executing' | 'disconnecting' | 'closed' | 'error';
  current_command: string | null;
  started_at: string;
  command_started_at: string | null;
  finished_at: string | null;
  elapsed_ms: number | null;
  last_error: string | null;
  source: 'local-probe' | 'python-mcp';
}

const deviceStore = new Map<string, RegisteredDevice>();
const activeSessions = new Map<string, LiveSSHSession>();
let recentSessions: LiveSSHSession[] = [];
const MAX_RECENT_SESSIONS = 25;

let upstreamWs: WebSocket | null = null;
let upstreamUrlConnected: string | null = null;

function isValidHostname(hostname: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9\-_.]{1,126}[A-Za-z0-9]$/.test(hostname);
}

function isPermittedMgmtIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 0) return false;
  if (version === 4) {
    if (ip.startsWith('127.') || ip.startsWith('169.254.') || ip === '0.0.0.0') return false;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::' || lower.startsWith('fe80:')) return false;
  }
  return true;
}

function isPermittedMcpUrl(rawUrl: string): URL | null {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.hostname === '169.254.169.254') return null;
    return parsed;
  } catch {
    return null;
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  const httpServer = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });

  // Handle WebSocket upgrade only for /ws/ssh-sessions (leaves Vite or other paths clean)
  httpServer.on('upgrade', (request, socket, head) => {
    const urlPath = (request.url || '').split('?')[0];
    if (urlPath === '/ws/ssh-sessions') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    }
  });

  function broadcastSessionEvent(event: Record<string, unknown>) {
    const payload = JSON.stringify(event);
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }

  wss.on('connection', (ws) => {
    ws.send(
      JSON.stringify({
        type: 'init',
        active_sessions: Array.from(activeSessions.values()),
        recent_sessions: recentSessions,
        upstream_mcp: upstreamUrlConnected,
      })
    );
  });

  function recordLocalSessionStart(device: {
    hostname: string;
    mgmtIp: string;
    sshPort: number;
    vendor: string;
    model: string;
    command: string;
  }): LiveSSHSession {
    const nowIso = new Date().toISOString();
    const session: LiveSSHSession = {
      session_id: `ssh-${crypto.randomUUID().slice(0, 10)}`,
      hostname: device.hostname,
      mgmt_ip: device.mgmtIp,
      ssh_port: device.sshPort,
      vendor: device.vendor,
      model: device.model,
      status: 'connecting',
      current_command: device.command,
      started_at: nowIso,
      command_started_at: nowIso,
      finished_at: null,
      elapsed_ms: 0,
      last_error: null,
      source: 'local-probe',
    };
    activeSessions.set(session.session_id, session);
    broadcastSessionEvent({ type: 'session:created', session });
    return session;
  }

  function updateLocalSession(
    sessionId: string,
    patch: Partial<LiveSSHSession>,
    eventType: 'session:updated' | 'session:closed' = 'session:updated'
  ) {
    const existing = activeSessions.get(sessionId);
    if (!existing) return;
    const updated: LiveSSHSession = { ...existing, ...patch };
    if (eventType === 'session:closed') {
      activeSessions.delete(sessionId);
      recentSessions = [updated, ...recentSessions].slice(0, MAX_RECENT_SESSIONS);
    } else {
      activeSessions.set(sessionId, updated);
    }
    broadcastSessionEvent({ type: eventType, session: updated });
  }

  function probeTcpSsh(
    deviceMeta: { hostname: string; mgmtIp: string; sshPort: number; vendor: string; model: string },
    timeoutMs = 4000
  ): Promise<{ reachable: boolean; latencyMs: number; banner: string | null; error: string | null }> {
    return new Promise((resolve) => {
      const started = Date.now();
      const session = recordLocalSessionStart({
        ...deviceMeta,
        command: `TCP connect ${deviceMeta.mgmtIp}:${deviceMeta.sshPort}`,
      });
      const socket = new net.Socket();
      let settled = false;
      let banner: string | null = null;

      const finish = (reachable: boolean, error: string | null) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        const latencyMs = Date.now() - started;
        updateLocalSession(
          session.session_id,
          {
            status: reachable ? 'closed' : 'error',
            current_command: null,
            finished_at: new Date().toISOString(),
            elapsed_ms: latencyMs,
            last_error: error,
          },
          'session:closed'
        );
        resolve({ reachable, latencyMs, banner, error });
      };

      socket.setTimeout(timeoutMs);
      socket.on('connect', () => {
        updateLocalSession(session.session_id, {
          status: 'executing',
          current_command: 'SSH-2.0 banner negotiation',
          command_started_at: new Date().toISOString(),
        });
        setTimeout(() => finish(true, null), 350);
      });
      socket.on('data', (chunk) => {
        const text = chunk.toString('utf8').trim();
        if (text.startsWith('SSH-')) {
          banner = text.split('\n')[0].trim();
          finish(true, null);
        }
      });
      socket.on('timeout', () =>
        finish(false, `TCP timeout after ${timeoutMs}ms connecting to ${deviceMeta.mgmtIp}:${deviceMeta.sshPort}`)
      );
      socket.on('error', (err) => finish(false, err.message));
      socket.connect(deviceMeta.sshPort, deviceMeta.mgmtIp);
    });
  }

  // 1. Read real files from /enterprise-switch-mcp
  app.get('/api/codebase', (req, res) => {
    const relPath = typeof req.query.file === 'string' ? req.query.file : '';
    const allowedFiles = [
      'src/switch_mcp/main.py',
      'src/switch_mcp/adapters/session_tracker.py',
      'src/switch_mcp/security/guardrails.py',
      'src/switch_mcp/security/rbac.py',
      'src/switch_mcp/security/vault.py',
      'src/switch_mcp/adapters/base.py',
      'src/switch_mcp/adapters/cisco_adapter.py',
      'src/switch_mcp/adapters/aruba_adapter.py',
      'src/switch_mcp/services/network_service.py',
      'src/switch_mcp/services/approval_service.py',
      'src/switch_mcp/services/audit_service.py',
      'src/switch_mcp/db/schema.sql',
      'src/switch_mcp/mcp/tools_device.py',
      'docker-compose.yml',
      'deploy/k8s/manifests.yaml',
    ];

    if (!relPath) {
      return res.json({ files: allowedFiles });
    }
    if (!allowedFiles.includes(relPath)) {
      return res.status(400).json({ error: 'Requested file is not in allowlist' });
    }
    const resolved = path.resolve(MCP_ROOT, relPath);
    if (!resolved.startsWith(MCP_ROOT + path.sep)) {
      return res.status(403).json({ error: 'Path traversal blocked' });
    }
    const content = fs.readFileSync(resolved, 'utf8');
    return res.json({ file: relPath, content });
  });

  // 2. Real SSH Sessions Snapshot
  app.get('/api/ssh/sessions', (_req, res) => {
    res.json({
      active_sessions: Array.from(activeSessions.values()),
      recent_sessions: recentSessions,
      upstream_mcp: upstreamUrlConnected,
    });
  });

  // 3. Connect/Disconnect Relay to Live Python MCP Server /ws/ssh-sessions
  app.post('/api/ssh/stream/connect', (req, res) => {
    const { mcpServerUrl, bearerToken } = req.body ?? {};
    const parsedUrl = isPermittedMcpUrl(String(mcpServerUrl || ''));
    if (!parsedUrl) {
      return res.status(400).json({ error: 'Valid http(s) MCP Server URL is required.' });
    }

    if (upstreamWs) {
      upstreamWs.close();
      upstreamWs = null;
      upstreamUrlConnected = null;
    }

    const wsProtocol = parsedUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    const targetWsUrl = `${wsProtocol}//${parsedUrl.host}/ws/ssh-sessions`;
    const wsClient = new WebSocket(targetWsUrl, {
      headers: bearerToken ? { Authorization: `Bearer ${String(bearerToken)}` } : undefined,
    });

    let responded = false;
    const timeout = setTimeout(() => {
      if (!responded) {
        responded = true;
        wsClient.close();
        res.status(504).json({ error: `Timed out connecting to ${targetWsUrl}` });
      }
    }, 5000);

    wsClient.on('open', () => {
      clearTimeout(timeout);
      upstreamWs = wsClient;
      upstreamUrlConnected = parsedUrl.origin;
      if (!responded) {
        responded = true;
        res.json({ connected: true, upstream: targetWsUrl });
      }
    });

    wsClient.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString('utf8'));
        if (msg.type === 'init') {
          if (Array.isArray(msg.active_sessions)) {
            for (const s of msg.active_sessions) {
              activeSessions.set(s.session_id, { ...s, source: 'python-mcp' });
            }
          }
          if (Array.isArray(msg.recent_sessions)) {
            recentSessions = msg.recent_sessions
              .map((s: LiveSSHSession) => ({ ...s, source: 'python-mcp' as const }))
              .slice(0, MAX_RECENT_SESSIONS);
          }
          broadcastSessionEvent({
            type: 'init',
            active_sessions: Array.from(activeSessions.values()),
            recent_sessions: recentSessions,
            upstream_mcp: upstreamUrlConnected,
          });
        } else if (msg.session) {
          const s: LiveSSHSession = { ...msg.session, source: 'python-mcp' };
          if (msg.type === 'session:closed') {
            activeSessions.delete(s.session_id);
            recentSessions = [s, ...recentSessions.filter((r) => r.session_id !== s.session_id)].slice(
              0,
              MAX_RECENT_SESSIONS
            );
          } else {
            activeSessions.set(s.session_id, s);
          }
          broadcastSessionEvent({ type: msg.type, session: s });
        }
      } catch {
        // ignore malformed upstream frame
      }
    });

    wsClient.on('error', (err) => {
      clearTimeout(timeout);
      if (!responded) {
        responded = true;
        res.status(502).json({ error: `Failed to connect to ${targetWsUrl}: ${err.message}` });
      }
    });

    wsClient.on('close', () => {
      if (upstreamWs === wsClient) {
        upstreamWs = null;
        upstreamUrlConnected = null;
        broadcastSessionEvent({
          type: 'init',
          active_sessions: Array.from(activeSessions.values()),
          recent_sessions: recentSessions,
          upstream_mcp: null,
        });
      }
    });
  });

  // 4. Real Device Inventory (empty until real devices are added by user)
  app.get('/api/devices', (_req, res) => {
    res.json({ devices: Array.from(deviceStore.values()) });
  });

  // 5. Real Device Onboarding + TCP/SSH Socket Check (or live MCP Server proxy)
  app.post('/api/devices', async (req, res) => {
    const {
      hostname,
      mgmtIp,
      sshPort = 22,
      vendor,
      model,
      siteCode = 'HQ-CORE',
      isStacked = false,
      sshUsername,
      sshPassword,
      enableSecret,
      mcpServerUrl,
      bearerToken,
    } = req.body ?? {};

    if (!hostname || !isValidHostname(String(hostname))) {
      return res.status(400).json({ error: 'Invalid switch hostname format.' });
    }
    if (!mgmtIp || !isPermittedMgmtIp(String(mgmtIp))) {
      return res.status(400).json({ error: 'Invalid or disallowed management IP address.' });
    }
    const portNum = Number(sshPort);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return res.status(400).json({ error: 'SSH port must be between 1 and 65535.' });
    }
    if (vendor !== 'cisco' && vendor !== 'aruba') {
      return res.status(400).json({ error: 'Vendor must be cisco or aruba.' });
    }
    if (!sshUsername || !sshPassword) {
      return res.status(400).json({ error: 'SSH username and password are required.' });
    }

    if (mcpServerUrl) {
      const parsedUrl = isPermittedMcpUrl(String(mcpServerUrl));
      if (!parsedUrl) {
        return res.status(400).json({ error: 'Invalid MCP Server URL.' });
      }
      try {
        const mcpResp = await fetch(`${parsedUrl.origin}/mcp`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(bearerToken ? { Authorization: `Bearer ${String(bearerToken)}` } : {}),
            'X-AI-Agent': 'netguard-control-plane',
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: Date.now(),
            method: 'tools/call',
            params: {
              name: 'add_device',
              arguments: {
                hostname: String(hostname).trim(),
                mgmt_ip: String(mgmtIp).trim(),
                vendor,
                model: String(model || ''),
                site_code: String(siteCode),
                ssh_username: String(sshUsername),
                ssh_password: String(sshPassword),
                ...(enableSecret ? { enable_secret: String(enableSecret) } : {}),
                ssh_port: portNum,
                is_stacked: Boolean(isStacked),
                verify_ssh: true,
              },
            },
          }),
        });
        const data = await mcpResp.json();
        return res.status(mcpResp.status).json({ mode: 'live_mcp_server', response: data });
      } catch (err) {
        return res.status(502).json({
          error: `Failed to reach live Python MCP Server at ${parsedUrl.origin}: ${(err as Error).message}`,
        });
      }
    }

    const probe = await probeTcpSsh({
      hostname: String(hostname).trim(),
      mgmtIp: String(mgmtIp).trim(),
      sshPort: portNum,
      vendor,
      model: String(model || ''),
    });
    const record: RegisteredDevice = {
      hostname: String(hostname).trim(),
      mgmtIp: String(mgmtIp).trim(),
      sshPort: portNum,
      vendor,
      model: String(model || ''),
      siteCode: String(siteCode),
      isStacked: Boolean(isStacked),
      sshUsername: String(sshUsername),
      vaultSecretPath: `secret/network/switches/${String(hostname).trim()}`,
      status: probe.reachable ? 'ssh_port_reachable' : 'unreachable',
      lastCheckedAt: new Date().toISOString(),
      lastLatencyMs: probe.latencyMs,
      lastError: probe.error,
    };
    deviceStore.set(record.hostname, record);

    return res.status(200).json({
      mode: 'direct_tcp_ssh_probe',
      device: record,
      probe,
    });
  });

  app.post('/api/devices/:hostname/test-ssh', async (req, res) => {
    const device = deviceStore.get(req.params.hostname);
    if (!device) {
      return res.status(404).json({ error: `Switch '${req.params.hostname}' is not registered.` });
    }
    const probe = await probeTcpSsh({
      hostname: device.hostname,
      mgmtIp: device.mgmtIp,
      sshPort: device.sshPort,
      vendor: device.vendor,
      model: device.model,
    });
    device.status = probe.reachable ? 'ssh_port_reachable' : 'unreachable';
    device.lastCheckedAt = new Date().toISOString();
    device.lastLatencyMs = probe.latencyMs;
    device.lastError = probe.error;
    deviceStore.set(device.hostname, device);
    return res.json({ device, probe });
  });

  app.delete('/api/devices/:hostname', (req, res) => {
    const deleted = deviceStore.delete(req.params.hostname);
    if (!deleted) {
      return res.status(404).json({ error: `Switch '${req.params.hostname}' not found.` });
    }
    return res.json({ deleted: req.params.hostname });
  });

  app.post('/api/mcp/health', async (req, res) => {
    const { mcpServerUrl } = req.body ?? {};
    const parsedUrl = isPermittedMcpUrl(String(mcpServerUrl || ''));
    if (!parsedUrl) {
      return res.status(400).json({ error: 'Valid http(s) MCP Server URL is required.' });
    }
    try {
      const resp = await fetch(`${parsedUrl.origin}/health`);
      const body = await resp.json();
      return res.status(resp.status).json(body);
    } catch (err) {
      return res.status(502).json({
        status: 'unreachable',
        error: (err as Error).message,
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: { server: httpServer } },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist/index.html'));
    });
  }

  httpServer.listen(3000, '0.0.0.0', () => {
    console.log('NetGuard MCP Control Plane + WebSocket Monitor running on http://0.0.0.0:3000');
  });
}

startServer();

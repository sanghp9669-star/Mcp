import React, { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Copy,
  Database,
  FileCode2,
  Layers,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  GUARDRAIL_BLOCKED_PATTERNS,
  MCP_RESOURCES,
  MCP_TOOLS,
  RiskLevel,
  RoleName,
  SUPPORTED_HARDWARE_MODELS,
} from './data/mcpCatalog';

type NavSection =
  | 'overview'
  | 'devices-ssh'
  | 'ssh-monitor'
  | 'tools-rbac'
  | 'codebase'
  | 'schema-deploy';

type WsConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'disconnected';

interface LiveSSHSession {
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

interface LiveDeviceRecord {
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

const ROLES: RoleName[] = ['SuperAdmin', 'NetworkAdmin', 'NOC', 'Auditor', 'Guest'];

const ARCHITECTURE_LAYERS = [
  { step: '01', name: 'AI Agent Client', tech: 'Claude Desktop · Cursor · LangGraph · Copilot', detail: 'Invokes MCP tools and reads network:// resources over Streamable HTTP / SSE.' },
  { step: '02', name: 'FastMCP Gateway', tech: 'Python 3.12 · FastMCP · FastAPI ASGI', detail: 'Validates Pydantic parameter schemas and isolates per-request context via ContextVar.' },
  { step: '03', name: 'Authentication Layer', tech: 'OAuth2 · OIDC JWKS · JWT RS256 · RFC 6238 TOTP', detail: 'Verifies token signature, claims, expiry, and Redis JTI revocation list.' },
  { step: '04', name: 'Authorization Layer (RBAC)', tech: '5 Roles · 49 Tools · 9 Resources', detail: 'Enforces Least Privilege across SuperAdmin, NetworkAdmin, NOC, Auditor, and Guest.' },
  { step: '05', name: 'AI Safe Guardrails & Approval', tech: 'Regex Policy Engine · 4-Tier Risk Workflow', detail: 'Blocks destructive CLI (reload, write erase, delete vlan.dat) and enforces 0/1/2/MFA+Ticket approvals.' },
  { step: '06', name: 'Immutable Audit Engine', tech: 'SHA-256 Hash Chain · PostgreSQL Trigger · RabbitMQ', detail: 'Appends tamper-evident audit records and ships events asynchronously to OpenSearch/ELK.' },
  { step: '07', name: 'Network Service & Locks', tech: 'Redis Sentinel Mutex · HashiCorp Vault KV v2', detail: 'Acquires distributed per-switch lock, takes pre-change snapshot, and pulls ephemeral credentials.' },
  { step: '08', name: 'Vendor Adapter Factory', tech: 'CiscoAdapter · ArubaAdapter · Netmiko · TextFSM', detail: 'Translates canonical operations into Cisco IOS & ArubaOS-Switch commands for standalone & stacks.' },
];

const DB_TABLES = [
  { name: 'users', purpose: 'Authenticated engineers and MFA Vault secret references' },
  { name: 'roles', purpose: '5 RBAC roles (SuperAdmin, NetworkAdmin, NOC, Auditor, Guest)' },
  { name: 'permissions', purpose: 'Granular role-to-tool and resource allowlist mappings' },
  { name: 'sites', purpose: 'Campus & datacenter site codes, regions, and timezones' },
  { name: 'devices', purpose: 'Cisco & Aruba switches, management IPs, stack counts, Vault paths' },
  { name: 'configs', purpose: 'Running and startup config snapshots with SHA-256 digests' },
  { name: 'backups', purpose: 'Pre-change and scheduled configuration backup ledger' },
  { name: 'change_requests', purpose: 'Change plans, CLI commands, risk tier, ticket IDs, workflow state' },
  { name: 'approvals', purpose: 'Multi-approver sign-off ledger with 4-eyes & MFA flags' },
  { name: 'audit_logs', purpose: 'Append-only hash-chained audit table protected by BEFORE UPDATE/DELETE trigger' },
  { name: 'tool_executions', purpose: 'Execution latency and status telemetry linked to audit_id' },
  { name: 'health_reports', purpose: 'Historical CPU, memory, thermal, and StackWise/VSF metrics' },
  { name: 'inventory', purpose: 'Chassis, stack member, PSU, and SFP serial inventory' },
];

export default function App() {
  const [activeNav, setActiveNav] = useState<NavSection>('overview');
  const [selectedRole, setSelectedRole] = useState<RoleName>('NetworkAdmin');

  // Live Python MCP Server connection settings (user-supplied, never mocked)
  const [mcpServerUrl, setMcpServerUrl] = useState<string>('');
  const [bearerToken, setBearerToken] = useState<string>('');
  const [mcpHealthResult, setMcpHealthResult] = useState<string>('');
  const [checkingMcp, setCheckingMcp] = useState<boolean>(false);

  // Real device inventory loaded from /api/devices (starts empty)
  const [devices, setDevices] = useState<LiveDeviceRecord[]>([]);
  const [loadingDevices, setLoadingDevices] = useState<boolean>(false);
  const [deviceError, setDeviceError] = useState<string>('');
  const [deviceActionOutput, setDeviceActionOutput] = useState<Record<string, unknown> | null>(null);

  // Add Device form (no fake pre-filled host/IPs)
  const [hostname, setHostname] = useState<string>('');
  const [mgmtIp, setMgmtIp] = useState<string>('');
  const [sshPort, setSshPort] = useState<string>('22');
  const [vendor, setVendor] = useState<'cisco' | 'aruba'>('cisco');
  const [model, setModel] = useState<string>('Catalyst 2960X');
  const [siteCode, setSiteCode] = useState<string>('');
  const [isStacked, setIsStacked] = useState<boolean>(false);
  const [sshUsername, setSshUsername] = useState<string>('');
  const [sshPassword, setSshPassword] = useState<string>('');
  const [enableSecret, setEnableSecret] = useState<string>('');
  const [submittingDevice, setSubmittingDevice] = useState<boolean>(false);

  // Tools & RBAC filter state
  const [toolSearch, setToolSearch] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [riskFilter, setRiskFilter] = useState<string>('All');

  // Real codebase inspector
  const [codeFiles, setCodeFiles] = useState<string[]>([]);
  const [selectedCodeFile, setSelectedCodeFile] = useState<string>('');
  const [codeContent, setCodeContent] = useState<string>('');
  const [loadingCode, setLoadingCode] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string>('');

  // Real-time SSH Session Monitoring state (WebSocket /ws/ssh-sessions)
  const [activeSessions, setActiveSessions] = useState<LiveSSHSession[]>([]);
  const [recentSessions, setRecentSessions] = useState<LiveSSHSession[]>([]);
  const [upstreamMcp, setUpstreamMcp] = useState<string | null>(null);
  const [wsState, setWsState] = useState<WsConnectionState>('connecting');
  const [streamError, setStreamError] = useState<string>('');
  const [attachingStream, setAttachingStream] = useState<boolean>(false);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());

  const fetchDevices = async () => {
    setLoadingDevices(true);
    try {
      const resp = await fetch('/api/devices');
      const data = await resp.json();
      setDevices(Array.isArray(data.devices) ? data.devices : []);
    } catch (err) {
      setDeviceError((err as Error).message);
    } finally {
      setLoadingDevices(false);
    }
  };

  const fetchCodebaseList = async () => {
    try {
      const resp = await fetch('/api/codebase');
      const data = await resp.json();
      const files: string[] = Array.isArray(data.files) ? data.files : [];
      setCodeFiles(files);
      if (files.length > 0 && !selectedCodeFile) {
        loadCodeFile(files[0]);
      }
    } catch {
      // handled cleanly in UI
    }
  };

  const loadCodeFile = async (file: string) => {
    setSelectedCodeFile(file);
    setLoadingCode(true);
    try {
      const resp = await fetch(`/api/codebase?file=${encodeURIComponent(file)}`);
      const data = await resp.json();
      setCodeContent(data.content || data.error || '');
    } catch (err) {
      setCodeContent(`Error loading file: ${(err as Error).message}`);
    } finally {
      setLoadingCode(false);
    }
  };

  const fetchSessionsSnapshot = async () => {
    try {
      const resp = await fetch('/api/ssh/sessions');
      if (!resp.ok) return;
      const data = await resp.json();
      setActiveSessions(Array.isArray(data.active_sessions) ? data.active_sessions : []);
      setRecentSessions(Array.isArray(data.recent_sessions) ? data.recent_sessions : []);
      setUpstreamMcp(typeof data.upstream_mcp === 'string' ? data.upstream_mcp : null);
    } catch {
      // WebSocket stream handles live recovery
    }
  };

  useEffect(() => {
    fetchDevices();
    fetchCodebaseList();
    fetchSessionsSnapshot();
  }, []);

  // Subscribe to real-time /ws/ssh-sessions stream with exponential backoff reconnect
  useEffect(() => {
    let unmounted = false;
    let ws: WebSocket | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let retryDelayMs = 1000;

    const connect = () => {
      if (unmounted) return;
      setWsState((prev) => (prev === 'disconnected' || prev === 'reconnecting' ? 'reconnecting' : 'connecting'));
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${window.location.host}/ws/ssh-sessions`);

      ws.onopen = () => {
        if (unmounted) return;
        retryDelayMs = 1000;
        setWsState('connected');
      };

      ws.onmessage = (evt) => {
        if (unmounted) return;
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'init') {
            setActiveSessions(Array.isArray(msg.active_sessions) ? msg.active_sessions : []);
            setRecentSessions(Array.isArray(msg.recent_sessions) ? msg.recent_sessions : []);
            setUpstreamMcp(typeof msg.upstream_mcp === 'string' ? msg.upstream_mcp : null);
          } else if ((msg.type === 'session:created' || msg.type === 'session:updated') && msg.session) {
            const incoming = msg.session as LiveSSHSession;
            setActiveSessions((prev) => {
              const filtered = prev.filter((s) => s.session_id !== incoming.session_id);
              return [incoming, ...filtered];
            });
          } else if (msg.type === 'session:closed' && msg.session) {
            const closed = msg.session as LiveSSHSession;
            setActiveSessions((prev) => prev.filter((s) => s.session_id !== closed.session_id));
            setRecentSessions((prev) =>
              [closed, ...prev.filter((s) => s.session_id !== closed.session_id)].slice(0, 25)
            );
          }
        } catch {
          // ignore malformed frames
        }
      };

      ws.onerror = () => {
        ws?.close();
      };

      ws.onclose = () => {
        if (unmounted) return;
        setWsState('reconnecting');
        const delay = retryDelayMs;
        retryDelayMs = Math.min(15000, Math.round(retryDelayMs * 1.6));
        retryTimer = setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      unmounted = true;
      if (retryTimer) clearTimeout(retryTimer);
      if (ws) ws.close();
    };
  }, []);

  // Tick local display clock only while real active SSH sessions exist
  useEffect(() => {
    if (activeSessions.length === 0) return;
    setNowMs(Date.now());
    const timer = setInterval(() => {
      setNowMs(Date.now());
    }, 250);
    return () => clearInterval(timer);
  }, [activeSessions.length]);

  const checkLiveMcpHealth = async () => {
    if (!mcpServerUrl.trim()) {
      setMcpHealthResult('Please enter a live Python MCP Server URL (e.g. http://localhost:8080).');
      return;
    }
    setCheckingMcp(true);
    setMcpHealthResult('');
    try {
      const resp = await fetch('/api/mcp/health', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mcpServerUrl: mcpServerUrl.trim() }),
      });
      const data = await resp.json();
      setMcpHealthResult(JSON.stringify(data, null, 2));
    } catch (err) {
      setMcpHealthResult(`Connection failed: ${(err as Error).message}`);
    } finally {
      setCheckingMcp(false);
    }
  };

  const handleAddDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    setDeviceError('');
    setDeviceActionOutput(null);
    setSubmittingDevice(true);
    try {
      const resp = await fetch('/api/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname: hostname.trim(),
          mgmtIp: mgmtIp.trim(),
          sshPort: Number(sshPort) || 22,
          vendor,
          model,
          siteCode: siteCode.trim() || 'HQ-CORE',
          isStacked,
          sshUsername: sshUsername.trim(),
          sshPassword,
          enableSecret: enableSecret || undefined,
          mcpServerUrl: mcpServerUrl.trim() || undefined,
          bearerToken: bearerToken.trim() || undefined,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setDeviceError(data.error || 'Failed to add device.');
      } else {
        setDeviceActionOutput(data);
        setSshPassword('');
        setEnableSecret('');
        await fetchDevices();
      }
    } catch (err) {
      setDeviceError((err as Error).message);
    } finally {
      setSubmittingDevice(false);
    }
  };

  const handleTestSsh = async (targetHost: string) => {
    setDeviceError('');
    try {
      const resp = await fetch(`/api/devices/${encodeURIComponent(targetHost)}/test-ssh`, {
        method: 'POST',
      });
      const data = await resp.json();
      setDeviceActionOutput(data);
      await fetchDevices();
    } catch (err) {
      setDeviceError((err as Error).message);
    }
  };

  const handleRemoveDevice = async (targetHost: string) => {
    setDeviceError('');
    try {
      const resp = await fetch(`/api/devices/${encodeURIComponent(targetHost)}`, {
        method: 'DELETE',
      });
      const data = await resp.json();
      setDeviceActionOutput(data);
      await fetchDevices();
    } catch (err) {
      setDeviceError((err as Error).message);
    }
  };

  const handleAttachMcpStream = async (e: React.FormEvent) => {
    e.preventDefault();
    setStreamError('');
    if (!mcpServerUrl.trim()) {
      setStreamError('Enter a live Python MCP Server URL (e.g. https://mcp.internal.corp:8080).');
      return;
    }
    setAttachingStream(true);
    try {
      const resp = await fetch('/api/ssh/stream/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mcpServerUrl: mcpServerUrl.trim(),
          bearerToken: bearerToken.trim() || undefined,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setStreamError(data.error || 'Failed to attach to upstream Python MCP WebSocket.');
      } else {
        await fetchSessionsSnapshot();
      }
    } catch (err) {
      setStreamError((err as Error).message);
    } finally {
      setAttachingStream(false);
    }
  };

  const formatElapsed = (isoStart: string | null, fixedMs: number | null) => {
    let ms = fixedMs;
    if (ms === null) {
      if (!isoStart) return '-';
      const parsed = Date.parse(isoStart);
      if (Number.isNaN(parsed)) return '-';
      ms = Math.max(0, nowMs - parsed);
    }
    if (ms < 1000) return `${Math.round(ms)} ms`;
    const totalSec = ms / 1000;
    if (totalSec < 60) return `${totalSec.toFixed(2)}s`;
    const mins = Math.floor(totalSec / 60);
    const remSec = (totalSec % 60).toFixed(1).padStart(4, '0');
    return `${mins}m ${remSec}s`;
  };

  const sessionStatusStyle = (status: LiveSSHSession['status']) => {
    switch (status) {
      case 'connecting':
        return 'text-amber-700 font-semibold';
      case 'connected':
        return 'text-emerald-700 font-semibold';
      case 'executing':
        return 'text-blue-700 font-semibold';
      case 'disconnecting':
        return 'text-slate-600 font-medium';
      case 'closed':
        return 'text-slate-600 font-medium';
      case 'error':
        return 'text-red-700 font-semibold';
    }
  };

  const sessionStatusLabel = (status: LiveSSHSession['status']) => {
    switch (status) {
      case 'connecting':
        return 'Connecting';
      case 'connected':
        return 'Connected (Idle)';
      case 'executing':
        return 'Executing';
      case 'disconnecting':
        return 'Disconnecting';
      case 'closed':
        return 'Closed';
      case 'error':
        return 'Error';
    }
  };

  const filteredTools = useMemo(() => {
    return MCP_TOOLS.filter((tool) => {
      const matchesSearch =
        tool.name.toLowerCase().includes(toolSearch.toLowerCase()) ||
        tool.description.toLowerCase().includes(toolSearch.toLowerCase());
      const matchesCat = categoryFilter === 'All' || tool.category === categoryFilter;
      const matchesRisk = riskFilter === 'All' || tool.risk === riskFilter;
      return matchesSearch && matchesCat && matchesRisk;
    });
  }, [toolSearch, categoryFilter, riskFilter]);

  const categories = useMemo(
    () => ['All', ...Array.from(new Set(MCP_TOOLS.map((t) => t.category)))],
    []
  );

  const copyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(''), 1800);
  };

  const riskTextClass = (risk: RiskLevel) => {
    switch (risk) {
      case 'LOW':
        return 'text-emerald-700 font-medium';
      case 'MEDIUM':
        return 'text-amber-700 font-medium';
      case 'HIGH':
        return 'text-orange-700 font-semibold';
      case 'CRITICAL':
        return 'text-red-700 font-semibold';
    }
  };

  const navItems: { id: NavSection; label: string; icon: React.ReactNode; count?: number }[] = [
    { id: 'overview', label: 'Architecture & MCP', icon: <Layers className="w-4 h-4" /> },
    { id: 'devices-ssh', label: 'Add Device & SSH', icon: <Network className="w-4 h-4" /> },
    {
      id: 'ssh-monitor',
      label: 'Live SSH Sessions',
      icon: <Terminal className="w-4 h-4" />,
      count: activeSessions.length > 0 ? activeSessions.length : undefined,
    },
    { id: 'tools-rbac', label: 'MCP Tools & RBAC (49)', icon: <ShieldCheck className="w-4 h-4" /> },
    { id: 'codebase', label: 'Python Source Code', icon: <FileCode2 className="w-4 h-4" /> },
    { id: 'schema-deploy', label: 'Schema & HA DevOps', icon: <Database className="w-4 h-4" /> },
  ];

  const breadcrumbLabel = navItems.find((n) => n.id === activeNav)?.label ?? 'Control Plane';

  return (
    <div className="min-h-screen flex bg-slate-50 text-slate-900">
      {/* Sidebar */}
      <aside className="w-60 shrink-0 bg-white border-r border-slate-200 flex flex-col justify-between">
        <div>
          <div className="h-14 px-5 flex items-center border-b border-slate-200">
            <span className="font-display text-base font-bold tracking-tight text-slate-900 whitespace-nowrap">
              NetGuard Switch MCP
            </span>
          </div>

          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const active = activeNav === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveNav(item.id)}
                  className={`w-full flex items-center justify-between gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                    active
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                  }`}
                >
                  <span className="flex items-center gap-2.5 min-w-0">
                    {item.icon}
                    <span className="truncate">{item.label}</span>
                  </span>
                  {item.count !== undefined && (
                    <span className="font-mono text-xs tabular-nums text-emerald-500">
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-4 border-t border-slate-200 text-xs text-slate-500 space-y-1">
          <div className="font-medium text-slate-700">Python 3.12 · FastMCP</div>
          <div>Cisco Catalyst · Aruba 2930</div>
          <div className="font-mono text-slate-400">enterprise-switch-mcp/</div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 px-6 bg-white border-b border-slate-200 flex items-center justify-between gap-8">
          <div className="flex items-center gap-2 text-sm text-slate-500 whitespace-nowrap">
            <span className="font-medium text-slate-900">Control Plane</span>
            <span aria-hidden="true">/</span>
            <span>{breadcrumbLabel}</span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <label htmlFor="role-select" className="text-xs font-medium text-slate-600 whitespace-nowrap">
              RBAC Matrix View
            </label>
            <select
              id="role-select"
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value as RoleName)}
              className="px-3 py-1.5 text-xs font-medium bg-white border border-slate-300 rounded-md text-slate-900"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
        </header>

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {/* VIEW 1: ARCHITECTURE & LIVE MCP SERVER CONNECTION */}
          {activeNav === 'overview' && (
            <>
              <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
                <div>
                  <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900">
                    Enterprise Multi-Vendor Switch MCP Architecture
                  </h1>
                  <p className="text-sm text-slate-600 mt-1">
                    Zero-Trust MCP automation server for Cisco Catalyst (3750CX, 2960, 2960S, 2960X) and Aruba (2930F, 2930M) standalone and stacked switches.
                  </p>
                </div>
                <div className="text-xs text-slate-500 font-mono tabular-nums whitespace-nowrap">
                  49 Tools · 9 Resources · 13 DB Tables · 5 RBAC Roles
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                <section className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-5">
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    Eight-Layer Zero-Trust Request Pipeline
                  </h2>
                  <p className="text-xs text-slate-500 mt-1 mb-4">
                    Every AI Agent tool call traverses authentication, RBAC, guardrails, approval verification, and SHA-256 audit chaining before touching SSH.
                  </p>
                  <div className="divide-y divide-slate-100">
                    {ARCHITECTURE_LAYERS.map((layer) => (
                      <div key={layer.step} className="py-2.5 flex items-start gap-3">
                        <span className="font-mono text-xs font-semibold text-slate-400 tabular-nums pt-0.5">
                          {layer.step}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-baseline justify-between gap-2">
                            <span className="text-sm font-semibold text-slate-900">{layer.name}</span>
                            <span className="text-xs font-mono text-slate-500">{layer.tech}</span>
                          </div>
                          <p className="text-xs text-slate-600 mt-0.5">{layer.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-5 space-y-4">
                  <div>
                    <h2 className="font-display text-base font-semibold text-slate-900">
                      Connect Live Python MCP Server
                    </h2>
                    <p className="text-xs text-slate-500 mt-1">
                      Point this console to your running FastMCP instance to verify real /health dependencies (PostgreSQL, Redis, RabbitMQ, Vault) and forward add_device SSH requests.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      MCP Server Base URL
                    </label>
                    <input
                      type="url"
                      value={mcpServerUrl}
                      onChange={(e) => setMcpServerUrl(e.target.value)}
                      placeholder="https://mcp.internal.corp:8080"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      OAuth2 Bearer JWT (Optional for /health, required for /mcp)
                    </label>
                    <input
                      type="password"
                      value={bearerToken}
                      onChange={(e) => setBearerToken(e.target.value)}
                      placeholder="Paste signed JWT token"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>

                  <button
                    type="button"
                    onClick={checkLiveMcpHealth}
                    disabled={checkingMcp}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white rounded-md"
                  >
                    <Play className="w-3.5 h-3.5" />
                    {checkingMcp ? 'Checking /health...' : 'Check Live /health'}
                  </button>

                  {mcpHealthResult && (
                    <pre className="bg-slate-950 text-slate-100 p-3.5 rounded-md text-xs font-mono overflow-x-auto">
                      {mcpHealthResult}
                    </pre>
                  )}

                  <div className="pt-2 border-t border-slate-100 space-y-2">
                    <div className="text-xs font-semibold text-slate-900">
                      AI Safe Guardrails (Always Blocked from Direct Execution)
                    </div>
                    <div className="text-xs font-mono text-slate-600 leading-relaxed">
                      {GUARDRAIL_BLOCKED_PATTERNS.join(' · ')}
                    </div>
                  </div>
                </section>
              </div>

              <section className="bg-white border border-slate-200 rounded-lg p-5">
                <h2 className="font-display text-base font-semibold text-slate-900">
                  Supported Switch Hardware Matrix (Standalone & Stack)
                </h2>
                <div className="overflow-x-auto mt-3">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-500">
                        <th className="py-2 pr-4">Vendor</th>
                        <th className="py-2 pr-4">Model</th>
                        <th className="py-2 pr-4">OS Family</th>
                        <th className="py-2 pr-4">Netmiko Driver</th>
                        <th className="py-2 pr-4">Stacking Support</th>
                        <th className="py-2">Stack Inspection Command</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {SUPPORTED_HARDWARE_MODELS.map((hw) => (
                        <tr key={hw.model}>
                          <td className="py-2.5 pr-4 uppercase font-mono text-slate-700">{hw.vendor}</td>
                          <td className="py-2.5 pr-4 font-semibold text-slate-900">{hw.model}</td>
                          <td className="py-2.5 pr-4 text-slate-600">{hw.osFamily}</td>
                          <td className="py-2.5 pr-4 font-mono text-slate-700">{hw.netmikoDriver}</td>
                          <td className="py-2.5 pr-4 text-slate-600">{hw.stackTechnology}</td>
                          <td className="py-2.5 font-mono text-slate-700">{hw.stackCommand}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {/* VIEW 2: REAL ADD DEVICE & SSH PROBE */}
          {activeNav === 'devices-ssh' && (
            <div className="space-y-6">
              <form onSubmit={handleAddDevice} className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
                <div>
                  <h1 className="font-display text-lg font-bold text-slate-900">
                    Add Switch Device & Connect via SSH (add_device)
                  </h1>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Performs a real TCP/SSH socket probe from the backend (or forwards to your live Python MCP Server when configured above).
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Switch Hostname *</label>
                    <input
                      required
                      type="text"
                      value={hostname}
                      onChange={(e) => setHostname(e.target.value)}
                      placeholder="Enter switch hostname"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Management IP *</label>
                    <input
                      required
                      type="text"
                      value={mgmtIp}
                      onChange={(e) => setMgmtIp(e.target.value)}
                      placeholder="Enter switch IPv4/IPv6"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">SSH Port</label>
                    <input
                      required
                      type="number"
                      min={1}
                      max={65535}
                      value={sshPort}
                      onChange={(e) => setSshPort(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Site Code</label>
                    <input
                      type="text"
                      value={siteCode}
                      onChange={(e) => setSiteCode(e.target.value)}
                      placeholder="HQ-CORE"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Vendor</label>
                    <select
                      value={vendor}
                      onChange={(e) => {
                        const v = e.target.value as 'cisco' | 'aruba';
                        setVendor(v);
                        setModel(v === 'cisco' ? 'Catalyst 2960X' : 'Aruba 2930F');
                      }}
                      className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white"
                    >
                      <option value="cisco">Cisco IOS</option>
                      <option value="aruba">ArubaOS-Switch</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">Hardware Model</label>
                    <select
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                      className="w-full px-3 py-2 text-xs border border-slate-300 rounded-md bg-white"
                    >
                      {vendor === 'cisco' ? (
                        <>
                          <option value="Catalyst 3750CX">Catalyst 3750CX</option>
                          <option value="Catalyst 2960">Catalyst 2960</option>
                          <option value="Catalyst 2960S">Catalyst 2960S</option>
                          <option value="Catalyst 2960X">Catalyst 2960X</option>
                        </>
                      ) : (
                        <>
                          <option value="Aruba 2930F">Aruba 2930F</option>
                          <option value="Aruba 2930M">Aruba 2930M</option>
                        </>
                      )}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">SSH Username *</label>
                    <input
                      required
                      type="text"
                      value={sshUsername}
                      onChange={(e) => setSshUsername(e.target.value)}
                      placeholder="SSH username"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">SSH Password *</label>
                    <input
                      required
                      type="password"
                      value={sshPassword}
                      onChange={(e) => setSshPassword(e.target.value)}
                      placeholder="SSH password"
                      className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
                  <div className="flex items-center gap-4">
                    <label className="inline-flex items-center gap-2 text-xs text-slate-700">
                      <input
                        type="checkbox"
                        checked={isStacked}
                        onChange={(e) => setIsStacked(e.target.checked)}
                        className="rounded border-slate-300"
                      />
                      Stacked Switch (FlexStack / VSF / Backplane)
                    </label>
                    <input
                      type="password"
                      value={enableSecret}
                      onChange={(e) => setEnableSecret(e.target.value)}
                      placeholder="Enable secret (optional)"
                      className="px-3 py-1.5 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submittingDevice}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white rounded-md"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    {submittingDevice ? 'Connecting SSH...' : 'Add Device & Test SSH'}
                  </button>
                </div>

                {deviceError && (
                  <div className="px-3.5 py-2 text-xs bg-red-50 border border-red-200 text-red-800 rounded-md">
                    {deviceError}
                  </div>
                )}

                {deviceActionOutput && (
                  <pre className="bg-slate-950 text-slate-100 p-3.5 rounded-md text-xs font-mono overflow-x-auto">
                    {JSON.stringify(deviceActionOutput, null, 2)}
                  </pre>
                )}
              </form>

              <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="font-display text-base font-semibold text-slate-900">
                      Registered Switch Inventory ({devices.length})
                    </h2>
                    <p className="text-xs text-slate-500">
                      Populated strictly from real user registrations and real socket/MCP responses.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={fetchDevices}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 rounded-md hover:bg-slate-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${loadingDevices ? 'animate-spin' : ''}`} />
                    Refresh
                  </button>
                </div>

                {devices.length === 0 ? (
                  <div className="py-10 text-center border border-dashed border-slate-200 rounded-md text-xs text-slate-500">
                    No switches registered yet. Add a real switch above to store it and test live SSH connectivity.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 text-slate-500">
                          <th className="py-2 pr-4">Hostname</th>
                          <th className="py-2 pr-4">Management IP:Port</th>
                          <th className="py-2 pr-4">Vendor / Model</th>
                          <th className="py-2 pr-4">Status</th>
                          <th className="py-2 pr-4">Latency</th>
                          <th className="py-2 pr-4">Last Error</th>
                          <th className="py-2 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {devices.map((d) => (
                          <tr key={d.hostname}>
                            <td className="py-2.5 pr-4 font-mono font-semibold text-slate-900">{d.hostname}</td>
                            <td className="py-2.5 pr-4 font-mono tabular-nums">{d.mgmtIp}:{d.sshPort}</td>
                            <td className="py-2.5 pr-4">{d.vendor.toUpperCase()} · {d.model}</td>
                            <td className="py-2.5 pr-4 font-mono">{d.status}</td>
                            <td className="py-2.5 pr-4 font-mono tabular-nums">
                              {d.lastLatencyMs !== null ? `${d.lastLatencyMs} ms` : '-'}
                            </td>
                            <td className="py-2.5 pr-4 text-red-700 font-mono truncate max-w-xs">
                              {d.lastError || '-'}
                            </td>
                            <td className="py-2.5 text-right space-x-2 whitespace-nowrap">
                              <button
                                type="button"
                                onClick={() => handleTestSsh(d.hostname)}
                                className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-white rounded text-xs"
                              >
                                Test SSH
                              </button>
                              <button
                                type="button"
                                onClick={() => handleRemoveDevice(d.hostname)}
                                className="inline-flex items-center gap-1 px-2 py-1 border border-slate-300 hover:bg-slate-100 text-slate-700 rounded text-xs"
                              >
                                <Trash2 className="w-3 h-3" />
                                Remove
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>
          )}

          {/* VIEW 2B: REAL-TIME SSH SESSION MONITOR */}
          {activeNav === 'ssh-monitor' && (
            <div className="space-y-6">
              <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
                <div>
                  <h1 className="font-display text-xl font-bold tracking-tight text-slate-900">
                    Real-Time SSH Session Monitor
                  </h1>
                  <p className="text-xs text-slate-600 mt-1">
                    Live telemetry over <span className="font-mono">/ws/ssh-sessions</span> showing active connection state, currently executing CLI command, and per-device elapsed time. Zero synthetic data.
                  </p>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-xs font-mono">
                    Stream:{' '}
                    <span
                      className={
                        wsState === 'connected'
                          ? 'text-emerald-700 font-semibold'
                          : wsState === 'reconnecting' || wsState === 'connecting'
                          ? 'text-amber-700 font-semibold'
                          : 'text-red-700 font-semibold'
                      }
                    >
                      {wsState === 'connected'
                        ? 'Connected'
                        : wsState === 'reconnecting'
                        ? 'Reconnecting'
                        : wsState === 'connecting'
                        ? 'Connecting'
                        : 'Disconnected'}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={fetchSessionsSnapshot}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-white border border-slate-300 rounded-md hover:bg-slate-50"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    Sync Snapshot
                  </button>
                </div>
              </div>

              {/* Live Summary Counters */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs font-medium text-slate-500">Active SSH Sessions</div>
                  <div className="font-display text-2xl font-bold text-slate-900 tabular-nums mt-1">
                    {activeSessions.length}
                  </div>
                </div>
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs font-medium text-slate-500">Executing CLI Command</div>
                  <div className="font-display text-2xl font-bold text-blue-700 tabular-nums mt-1">
                    {activeSessions.filter((s) => s.status === 'executing').length}
                  </div>
                </div>
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs font-medium text-slate-500">Connected / Handshaking</div>
                  <div className="font-display text-2xl font-bold text-emerald-700 tabular-nums mt-1">
                    {
                      activeSessions.filter(
                        (s) => s.status === 'connected' || s.status === 'connecting'
                      ).length
                    }
                  </div>
                </div>
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs font-medium text-slate-500">Recent Completed / Failed</div>
                  <div className="font-display text-2xl font-bold text-slate-700 tabular-nums mt-1">
                    {recentSessions.length}
                  </div>
                </div>
              </div>

              {/* Upstream Python MCP Stream Relay + Quick Real Device Probe */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
                <form
                  onSubmit={handleAttachMcpStream}
                  className="lg:col-span-7 bg-white border border-slate-200 rounded-lg p-4 space-y-3"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <h2 className="font-display text-sm font-semibold text-slate-900">
                      Upstream Python MCP Stream Relay
                    </h2>
                    <span className="text-xs font-mono text-slate-500">
                      {upstreamMcp ? `Relaying: ${upstreamMcp}` : 'Local probe stream only'}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <input
                      type="url"
                      value={mcpServerUrl}
                      onChange={(e) => setMcpServerUrl(e.target.value)}
                      placeholder="https://mcp.internal.corp:8080"
                      className="px-3 py-1.5 text-xs font-mono border border-slate-300 rounded-md"
                    />
                    <input
                      type="password"
                      value={bearerToken}
                      onChange={(e) => setBearerToken(e.target.value)}
                      placeholder="OAuth2 Bearer JWT (if auth enabled)"
                      className="px-3 py-1.5 text-xs font-mono border border-slate-300 rounded-md"
                    />
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-slate-500">
                      Forwards live Netmiko SSH events from FastMCP <span className="font-mono">/ws/ssh-sessions</span>.
                    </span>
                    <button
                      type="submit"
                      disabled={attachingStream}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white rounded-md shrink-0"
                    >
                      <Play className="w-3 h-3" />
                      {attachingStream ? 'Connecting...' : 'Attach MCP Stream'}
                    </button>
                  </div>
                  {streamError && (
                    <div className="px-3 py-2 text-xs bg-red-50 border border-red-200 text-red-800 rounded-md">
                      {streamError}
                    </div>
                  )}
                </form>

                <div className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <h2 className="font-display text-sm font-semibold text-slate-900">
                      Trigger Real Switch Probe
                    </h2>
                    <button
                      type="button"
                      onClick={() => setActiveNav('devices-ssh')}
                      className="text-xs font-medium text-slate-700 hover:text-slate-900 underline"
                    >
                      Manage Devices
                    </button>
                  </div>
                  {devices.length === 0 ? (
                    <p className="text-xs text-slate-500 py-2">
                      No switches registered yet. Add a real switch in <span className="font-medium text-slate-700">Add Device &amp; SSH</span> or attach an upstream Python MCP Server to observe live SSH sessions.
                    </p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {devices.map((d) => (
                        <button
                          key={d.hostname}
                          type="button"
                          onClick={() => handleTestSsh(d.hostname)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-white rounded-md"
                        >
                          <Play className="w-3 h-3" />
                          Test {d.hostname}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Active SSH Sessions Table */}
              <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    Active SSH Sessions ({activeSessions.length})
                  </h2>
                  <span className="text-xs font-mono text-slate-500 tabular-nums">
                    Updated via WebSocket events
                  </span>
                </div>

                {activeSessions.length === 0 ? (
                  <div className="p-10 text-center text-xs text-slate-500 space-y-2">
                    <div className="font-medium text-slate-700">
                      No active SSH sessions currently open.
                    </div>
                    <div>
                      Sessions appear here in real time whenever a switch probe or Python FastMCP adapter connects, negotiates SSH, or executes CLI commands.
                    </div>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold">
                          <th className="py-2.5 px-4">Device</th>
                          <th className="py-2.5 px-3">IP : Port</th>
                          <th className="py-2.5 px-3">Vendor / Model</th>
                          <th className="py-2.5 px-3">Connection Status</th>
                          <th className="py-2.5 px-3">Current Command</th>
                          <th className="py-2.5 px-3">Command Elapsed</th>
                          <th className="py-2.5 px-3">Session Elapsed</th>
                          <th className="py-2.5 px-4">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {activeSessions.map((session) => (
                          <tr key={session.session_id} className="hover:bg-slate-50">
                            <td className="py-2.5 px-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                              {session.hostname}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                              {session.mgmt_ip}:{session.ssh_port}
                            </td>
                            <td className="py-2.5 px-3 text-slate-700 whitespace-nowrap">
                              {session.vendor.toUpperCase()} · {session.model || '-'}
                            </td>
                            <td className={`py-2.5 px-3 whitespace-nowrap ${sessionStatusStyle(session.status)}`}>
                              {sessionStatusLabel(session.status)}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-slate-900 max-w-xs truncate">
                              {session.current_command || (session.status === 'connected' ? 'Idle (awaiting command)' : '-')}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                              {session.command_started_at
                                ? formatElapsed(session.command_started_at, null)
                                : '-'}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums font-semibold text-slate-900 whitespace-nowrap">
                              {formatElapsed(session.started_at, null)}
                            </td>
                            <td className="py-2.5 px-4 font-mono text-slate-500 whitespace-nowrap">
                              {session.source}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {/* Recent Completed / Failed Sessions */}
              <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
                  <h2 className="font-display text-base font-semibold text-slate-900">
                    Recent Session History ({recentSessions.length})
                  </h2>
                  <span className="text-xs text-slate-500">
                    Last 25 completed or errored SSH sessions from this server session
                  </span>
                </div>

                {recentSessions.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No SSH sessions have completed yet in this server process.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-semibold">
                          <th className="py-2.5 px-4">Device</th>
                          <th className="py-2.5 px-3">IP : Port</th>
                          <th className="py-2.5 px-3">Final Status</th>
                          <th className="py-2.5 px-3">Duration</th>
                          <th className="py-2.5 px-3">Finished At</th>
                          <th className="py-2.5 px-3">Error Detail</th>
                          <th className="py-2.5 px-4">Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {recentSessions.map((session) => (
                          <tr key={session.session_id} className="hover:bg-slate-50">
                            <td className="py-2.5 px-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                              {session.hostname}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-slate-700 whitespace-nowrap">
                              {session.mgmt_ip}:{session.ssh_port}
                            </td>
                            <td className={`py-2.5 px-3 whitespace-nowrap ${sessionStatusStyle(session.status)}`}>
                              {sessionStatusLabel(session.status)}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-slate-900 whitespace-nowrap">
                              {formatElapsed(session.started_at, session.elapsed_ms)}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-slate-500 whitespace-nowrap">
                              {session.finished_at
                                ? new Date(session.finished_at).toLocaleTimeString()
                                : '-'}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-red-700 max-w-sm truncate">
                              {session.last_error || '-'}
                            </td>
                            <td className="py-2.5 px-4 font-mono text-slate-500 whitespace-nowrap">
                              {session.source}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>
          )}

          {/* VIEW 3: MCP TOOLS & RBAC MATRIX */}
          {activeNav === 'tools-rbac' && (
            <section className="space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div>
                  <h1 className="font-display text-xl font-bold text-slate-900">
                    MCP Tool Catalog & Five-Role RBAC Matrix
                  </h1>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Showing permission matrix for role <strong className="text-slate-900">{selectedRole}</strong> across all 49 registered tools.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                    <input
                      type="text"
                      value={toolSearch}
                      onChange={(e) => setToolSearch(e.target.value)}
                      placeholder="Filter tools..."
                      className="pl-8 pr-3 py-1.5 text-xs bg-white border border-slate-300 rounded-md w-48"
                    />
                  </div>
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    className="px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md"
                  >
                    {categories.map((c) => (
                      <option key={c} value={c}>
                        {c === 'All' ? 'All Categories' : c}
                      </option>
                    ))}
                  </select>
                  <select
                    value={riskFilter}
                    onChange={(e) => setRiskFilter(e.target.value)}
                    className="px-2.5 py-1.5 text-xs bg-white border border-slate-300 rounded-md"
                  >
                    <option value="All">All Risks</option>
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>

              <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                        <th className="py-2.5 px-4">Tool Name</th>
                        <th className="py-2.5 px-3">Domain</th>
                        <th className="py-2.5 px-3">Risk</th>
                        <th className="py-2.5 px-3">Schema Parameters</th>
                        <th className="py-2.5 px-3">{selectedRole}</th>
                        <th className="py-2.5 px-4">Allowed Roles</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-xs">
                      {filteredTools.map((tool) => {
                        const permitted = tool.roles.includes(selectedRole);
                        return (
                          <tr key={tool.name} className="hover:bg-slate-50">
                            <td className="py-2.5 px-4 font-mono font-medium text-slate-900">
                              {tool.name}
                            </td>
                            <td className="py-2.5 px-3 text-slate-600">{tool.category}</td>
                            <td className={`py-2.5 px-3 font-mono ${riskTextClass(tool.risk)}`}>
                              {tool.risk}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-slate-500">{tool.params}</td>
                            <td className="py-2.5 px-3">
                              {permitted ? (
                                <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
                                  <CheckCircle2 className="w-3.5 h-3.5" /> Allowed
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 text-slate-400">
                                  <XCircle className="w-3.5 h-3.5" /> Denied
                                </span>
                              )}
                            </td>
                            <td className="py-2.5 px-4 text-slate-500">
                              {tool.roles.join(' · ')}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              <section className="bg-white border border-slate-200 rounded-lg p-5">
                <h2 className="font-display text-base font-semibold text-slate-900">
                  MCP Resources (9 Live Context Endpoints)
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-3">
                  {MCP_RESOURCES.map((res) => (
                    <div key={res.uri} className="border border-slate-200 rounded-md p-3.5">
                      <div className="font-mono text-xs font-semibold text-slate-900">{res.uri}</div>
                      <div className="text-xs text-slate-500 mt-1">{res.description}</div>
                      <div className="text-xs text-slate-400 mt-2">Access: {res.scope}</div>
                    </div>
                  ))}
                </div>
              </section>
            </section>
          )}

          {/* VIEW 4: REAL PYTHON SOURCE CODE INSPECTOR */}
          {activeNav === 'codebase' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
              <aside className="lg:col-span-4 bg-white border border-slate-200 rounded-lg p-4 space-y-1">
                <div className="text-xs font-semibold text-slate-900 pb-2 border-b border-slate-100">
                  enterprise-switch-mcp/ Source Files
                </div>
                {codeFiles.map((file) => (
                  <button
                    key={file}
                    type="button"
                    onClick={() => loadCodeFile(file)}
                    className={`w-full text-left px-2.5 py-1.5 rounded text-xs font-mono transition-colors ${
                      selectedCodeFile === file
                        ? 'bg-slate-900 text-white'
                        : 'text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    {file}
                  </button>
                ))}
              </aside>

              <section className="lg:col-span-8 bg-white border border-slate-200 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between gap-4">
                  <span className="font-mono text-xs font-semibold text-slate-900 truncate">
                    {selectedCodeFile || 'Select a file'}
                  </span>
                  {codeContent && (
                    <button
                      type="button"
                      onClick={() => copyText('source', codeContent)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 rounded-md hover:bg-slate-50 shrink-0"
                    >
                      <Copy className="w-3.5 h-3.5" />
                      {copiedKey === 'source' ? 'Copied' : 'Copy Source'}
                    </button>
                  )}
                </div>
                <pre className="bg-slate-950 text-slate-100 p-4 rounded-md text-xs font-mono overflow-x-auto max-h-[640px] leading-relaxed">
                  {loadingCode ? 'Loading real file from disk...' : codeContent}
                </pre>
              </section>
            </div>
          )}

          {/* VIEW 5: DATABASE SCHEMA & HA DEVOPS */}
          {activeNav === 'schema-deploy' && (
            <div className="space-y-6">
              <section className="bg-white border border-slate-200 rounded-lg p-5">
                <h2 className="font-display text-lg font-bold text-slate-900">
                  PostgreSQL 16 Schema (13 Normalized Tables)
                </h2>
                <p className="text-xs text-slate-600 mt-0.5 mb-4">
                  Defined in <span className="font-mono">enterprise-switch-mcp/src/switch_mcp/db/schema.sql</span> with Primary/Replica read-write split.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {DB_TABLES.map((tbl) => (
                    <div key={tbl.name} className="border border-slate-200 rounded-md p-3">
                      <div className="font-mono text-xs font-semibold text-slate-900">{tbl.name}</div>
                      <div className="text-xs text-slate-600 mt-1">{tbl.purpose}</div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="font-display text-lg font-bold text-slate-900">
                      Production Deployment Commands (Docker & Kubernetes Helm)
                    </h2>
                    <p className="text-xs text-slate-600">
                      Active-Active MCP Server replicas behind NGINX / K8s Service with PostgreSQL Replication, Redis Sentinel, RabbitMQ, Vault, and Prometheus/OTEL.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      copyText(
                        'deploy',
                        'cd enterprise-switch-mcp && cp .env.example .env && docker compose up -d --build'
                      )
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 rounded-md hover:bg-slate-50"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    {copiedKey === 'deploy' ? 'Copied' : 'Copy Quickstart'}
                  </button>
                </div>

                <pre className="bg-slate-950 text-slate-100 p-4 rounded-md text-xs font-mono overflow-x-auto leading-relaxed">
{`# 1. Start Active-Active HA Stack (MCP x2 + NGINX + PG Primary/Replica + Redis Sentinel + RabbitMQ + Vault + OTEL)
cd enterprise-switch-mcp
cp .env.example .env
docker compose up -d --build

# 2. Run Unit, Security (Bandit), and Integration Tests
pytest tests/unit tests/security tests/integration -v --cov=switch_mcp
bandit -r src -ll

# 3. Deploy onto Kubernetes via Helm Chart (HPA 3..12 pods, PDB minAvailable=2, NetworkPolicy)
helm upgrade --install switch-mcp ./deploy/helm/switch-mcp \\
  --namespace netops-mcp --create-namespace \\
  -f ./deploy/helm/switch-mcp/values.yaml`}
                </pre>
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

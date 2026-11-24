# Enterprise Switch MCP Server (Cisco Catalyst & ArubaOS-Switch)

## Project Overview
Enterprise-grade Model Context Protocol (MCP) server enabling AI Agents (Claude Desktop, Cursor, VS Code Copilot, OpenAI Agents, LangGraph) to inspect, troubleshoot, audit, and safely manage enterprise campus switching infrastructure with Zero-Trust security, 5-role RBAC, multi-stage Approval Workflows, AI Safe Guardrails, and Immutable Audit Logging.

### Supported Hardware (Standalone & Stack)
- **Cisco IOS**: Catalyst 3750CX, Catalyst 2960, Catalyst 2960S (FlexStack), Catalyst 2960X (FlexStack-Plus)
- **ArubaOS-Switch**: Aruba 2930F (VSF), Aruba 2930M (Backplane Stacking)

### Main Features
- 46 production MCP Tools across 9 operational domains (Device, VLAN, Port, Backup, Troubleshooting, Security, Inventory, Health, Approval)
- 9 MCP Resources (`network://devices`, `network://inventory`, `network://vlans`, `network://configs`, `network://backups`, `network://health`, `network://topology`, `network://auditlogs`, `network://approvals`)
- Multi-Vendor Factory & Adapter Abstraction (`SwitchAdapter`, `CiscoAdapter`, `ArubaAdapter`)
- AI Safe Guardrails blocking destructive operations (`reload`, `write erase`, `delete vlan.dat`, etc.) and forcing Change Plan + Risk Analysis + Approval
- SHA-256 hash-chained Immutable Audit Log in PostgreSQL + RabbitMQ async shipping to OpenSearch/ELK
- Active-Active High Availability with Redis Sentinel distributed device locking

## Architecture
Layered Zero-Trust architecture:
`AI Agent -> FastMCP Server -> OAuth2/JWT Authentication -> 5-Role RBAC Authorization -> AI Safe Guardrails & Approval Engine -> Immutable Audit Engine -> Network Service Layer -> Adapter Factory (CiscoAdapter / ArubaAdapter) -> SSH Connection Layer (Netmiko/NAPALM/AsyncSSH) -> Switches`

## Prerequisites
- Python 3.12+
- PostgreSQL 16+ (Primary + Read Replica)
- Redis 7+ (Sentinel or Cluster mode)
- RabbitMQ 3.13+ (Cluster)
- HashiCorp Vault 1.17+ (KV v2 & AppRole enabled)
- Docker 25+ & Kubernetes 1.30+ / Helm 3.14+ (for production HA deployment)

## Installation
```bash
cd enterprise-switch-mcp
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

## Configuration
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Initialize PostgreSQL schema:
   ```bash
   psql "$POSTGRES_DSN" -f src/switch_mcp/db/schema.sql
   ```
3. Store device SSH credentials in HashiCorp Vault under `secret/data/network/switches/<device_id>`.

## Running the Application
### Development Mode
```bash
uvicorn switch_mcp.main:app --host 0.0.0.0 --port 8080 --reload
```
### Production Mode (Docker Compose HA Stack)
```bash
docker compose up -d --build
```

## Running Tests
### Unit & Security Tests
```bash
pytest tests/unit tests/security -v --cov=switch_mcp
bandit -r src/
```
### Integration Tests
```bash
pytest tests/integration -v
```
### Load Tests
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8080
```

## API Documentation
- `POST /mcp` — Streamable HTTP MCP endpoint for AI Agents (Bearer JWT required)
- `GET /health` — Aggregated dependency health check (PostgreSQL, Redis, Vault, RabbitMQ)
- `GET /liveness` — Kubernetes liveness probe
- `GET /readiness` — Kubernetes readiness probe verifying downstream pools
- `GET /metrics` — Prometheus exposition endpoint

## Deployment
Deploy via Helm onto Kubernetes:
```bash
helm upgrade --install switch-mcp ./deploy/helm/switch-mcp \
  --namespace netops-mcp --create-namespace \
  -f ./deploy/helm/switch-mcp/values.yaml
```

## Troubleshooting
- **SSH Host Key Mismatch**: Ensure switch SSH public keys are pre-loaded into `/etc/switch_mcp/known_hosts` when `SSH_STRICT_HOST_KEY_CHECKING=true`.
- **Approval Blocked (CRITICAL)**: Verify `mfa_code` (6-digit TOTP) and `change_ticket` (e.g. `CHG-2026-0042`) are passed by a `SuperAdmin`.
- **Distributed Lock Timeout**: If a long-running backup holds a device lock, check Redis key `lock:switch:<device_id>`.

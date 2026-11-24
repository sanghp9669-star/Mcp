-- =============================================================================
-- Enterprise Switch MCP Server - PostgreSQL 16 Schema (13 Core Tables)
-- Enforces referential integrity, RBAC, Change Management, and Immutable Audit
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. ROLES
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(32) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. PERMISSIONS
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tool_or_resource VARCHAR(128) NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (role_id, tool_or_resource)
);

-- 3. USERS
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id),
    mfa_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_secret_vault_path VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. SITES
CREATE TABLE IF NOT EXISTS sites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_code VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    region VARCHAR(64) NOT NULL,
    timezone VARCHAR(64) NOT NULL DEFAULT 'UTC',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. DEVICES
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id UUID NOT NULL REFERENCES sites(id),
    hostname VARCHAR(128) UNIQUE NOT NULL,
    mgmt_ip INET NOT NULL,
    ssh_port INTEGER NOT NULL DEFAULT 22,
    vendor VARCHAR(32) NOT NULL CHECK (vendor IN ('cisco', 'aruba')),
    model VARCHAR(64) NOT NULL,
    os_version VARCHAR(64),
    serial_number VARCHAR(64),
    is_stacked BOOLEAN NOT NULL DEFAULT FALSE,
    stack_count INTEGER NOT NULL DEFAULT 1,
    vault_secret_path VARCHAR(255) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'online',
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_devices_site ON devices(site_id);
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor);

-- 6. CONFIGS
CREATE TABLE IF NOT EXISTS configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    config_type VARCHAR(16) NOT NULL CHECK (config_type IN ('running', 'startup')),
    config_text TEXT NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    collected_by VARCHAR(64) NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_configs_device_time ON configs(device_id, collected_at DESC);

-- 7. BACKUPS
CREATE TABLE IF NOT EXISTS backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    config_id UUID NOT NULL REFERENCES configs(id),
    backup_type VARCHAR(16) NOT NULL CHECK (backup_type IN ('running', 'startup', 'pre_change')),
    storage_uri VARCHAR(512),
    sha256_hash CHAR(64) NOT NULL,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_backups_device ON backups(device_id, created_at DESC);

-- 8. CHANGE REQUESTS
CREATE TABLE IF NOT EXISTS change_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_code VARCHAR(32) UNIQUE NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id),
    requested_by UUID NOT NULL REFERENCES users(id),
    ai_agent VARCHAR(64) NOT NULL,
    tool_name VARCHAR(64) NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    change_plan JSONB NOT NULL,
    cli_commands JSONB NOT NULL,
    risk_level VARCHAR(16) NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    required_approvals INTEGER NOT NULL DEFAULT 1,
    requires_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    change_ticket VARCHAR(64),
    status VARCHAR(24) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'FAILED', 'BLOCKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cr_status ON change_requests(status, created_at DESC);

-- 9. APPROVALS
CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    change_request_id UUID NOT NULL REFERENCES change_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES users(id),
    decision VARCHAR(16) NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    comment TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (change_request_id, approver_id)
);

-- 10. AUDIT LOGS (IMMUTABLE APPEND-ONLY WITH HASH CHAIN)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    audit_id VARCHAR(32) UNIQUE NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    username VARCHAR(64) NOT NULL,
    role_name VARCHAR(32) NOT NULL,
    ai_agent VARCHAR(64) NOT NULL,
    source_ip INET NOT NULL,
    tool_name VARCHAR(64) NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    device_hostname VARCHAR(128),
    result_status VARCHAR(24) NOT NULL,
    result_summary TEXT NOT NULL,
    approval_id VARCHAR(64),
    risk_level VARCHAR(16) NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    record_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_logs(device_hostname);

-- Enforce immutability at database engine level
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is immutable: % operations are forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_update ON audit_logs;
CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

-- 11. TOOL EXECUTIONS
CREATE TABLE IF NOT EXISTS tool_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(32) NOT NULL REFERENCES audit_logs(audit_id),
    device_id UUID REFERENCES devices(id),
    tool_name VARCHAR(64) NOT NULL,
    duration_ms INTEGER NOT NULL,
    status VARCHAR(24) NOT NULL,
    error_message TEXT,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12. HEALTH REPORTS
CREATE TABLE IF NOT EXISTS health_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    cpu_5min_pct NUMERIC(5,2) NOT NULL,
    memory_used_pct NUMERIC(5,2) NOT NULL,
    temperature_celsius NUMERIC(5,2),
    stack_status VARCHAR(24) NOT NULL,
    raw_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_health_device_time ON health_reports(device_id, recorded_at DESC);

-- 13. INVENTORY
CREATE TABLE IF NOT EXISTS inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    slot_name VARCHAR(64) NOT NULL,
    model VARCHAR(64) NOT NULL,
    serial_number VARCHAR(64) NOT NULL,
    firmware_version VARCHAR(64),
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, slot_name)
);

-- Seed Default RBAC Roles
INSERT INTO roles (name, description) VALUES
    ('SuperAdmin', 'Full infrastructure & CRITICAL MFA+Ticket approval access'),
    ('NetworkAdmin', 'Configuration, VLAN, Port, Backup/Restore, and MEDIUM/HIGH approvals'),
    ('NOC', 'Read-only monitoring and Layer 1/2/3 troubleshooting'),
    ('Auditor', 'Read-only configs, security compliance scans, and immutable audit logs'),
    ('Guest', 'Limited read-only topology and device health overview')
ON CONFLICT (name) DO NOTHING;

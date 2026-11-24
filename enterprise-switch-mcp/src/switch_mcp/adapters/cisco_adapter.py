"""Cisco IOS Adapter supporting Catalyst 3750CX, 2960, 2960S, and 2960X (Standalone & Stack)."""

import asyncio
import re
from pathlib import Path
from typing import Any

import textfsm
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from switch_mcp.adapters.base import (
    DeviceConnectionSpec,
    HealthMetrics,
    InterfaceRecord,
    InventoryItem,
    NeighborRecord,
    SwitchAdapter,
    SwitchFacts,
    VlanRecord,
)
from switch_mcp.adapters.session_tracker import ssh_session_tracker
from switch_mcp.core.exceptions import CommandExecutionError, DeviceConnectionError
from switch_mcp.core.telemetry import ACTIVE_SSH_SESSIONS
from switch_mcp.security.guardrails import AISafeGuardrails

_TEMPLATE_DIR = Path(__file__).parent / "templates"


class CiscoAdapter(SwitchAdapter):
    """Production adapter for Cisco Catalyst IOS switches via Netmiko + TextFSM."""

    SUPPORTED_MODELS = frozenset({
        "Catalyst 3750CX",
        "WS-C3750CX-12PD-S",
        "Catalyst 2960",
        "Catalyst 2960S",
        "Catalyst 2960X",
    })

    def __init__(self, spec: DeviceConnectionSpec) -> None:
        super().__init__(spec)
        self._conn: Any = None
        self._session_id: str | None = None

    async def connect(self) -> None:
        self._session_id = await ssh_session_tracker.start_session(
            hostname=self.spec.hostname,
            mgmt_ip=self.spec.mgmt_ip,
            ssh_port=self.spec.port,
            vendor="cisco",
            model=self.spec.model,
        )

        def _connect() -> Any:
            import os
            import tempfile

            key_path: str | None = None
            try:
                params: dict[str, Any] = {
                    "device_type": "cisco_ios",
                    "host": self.spec.mgmt_ip,
                    "port": self.spec.port,
                    "username": self.spec.username,
                    "password": self.spec.password,
                    "secret": self.spec.enable_secret or self.spec.password,
                    "conn_timeout": self.spec.connect_timeout,
                    "read_timeout_override": self.spec.command_timeout,
                }
                if self.spec.ssh_private_key:
                    fd, key_path = tempfile.mkstemp(prefix="mcp_ssh_", suffix=".pem")
                    os.chmod(key_path, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as fh:
                        fh.write(self.spec.ssh_private_key)
                    params["use_keys"] = True
                    params["key_file"] = key_path

                conn = ConnectHandler(**params)
                if not conn.check_enable_mode():
                    conn.enable()
                return conn
            finally:
                if key_path and os.path.exists(key_path):
                    os.unlink(key_path)

        try:
            self._conn = await asyncio.to_thread(_connect)
            self._connected = True
            ACTIVE_SSH_SESSIONS.labels(vendor="cisco").inc()
            if self._session_id:
                await ssh_session_tracker.mark_connected(self._session_id)
        except (NetmikoAuthenticationException, NetmikoTimeoutException, OSError) as exc:
            if self._session_id:
                await ssh_session_tracker.end_session(self._session_id, error=str(exc))
                self._session_id = None
            raise DeviceConnectionError(
                f"Failed to connect to Cisco switch {self.spec.hostname} ({self.spec.mgmt_ip}): {exc}"
            ) from exc

    async def disconnect(self) -> None:
        if self._conn is not None:
            try:
                await asyncio.to_thread(self._conn.disconnect)
            finally:
                self._conn = None
                if self._connected:
                    ACTIVE_SSH_SESSIONS.labels(vendor="cisco").dec()
                self._connected = False
        if self._session_id:
            await ssh_session_tracker.end_session(self._session_id)
            self._session_id = None

    async def execute_show(self, command: str) -> str:
        if not self._conn:
            raise DeviceConnectionError("Not connected to Cisco device")
        AISafeGuardrails.inspect_commands("execute_show", command, vendor="cisco_ios")
        if self._session_id:
            await ssh_session_tracker.mark_executing(self._session_id, command)
        try:
            return await asyncio.to_thread(
                self._conn.send_command, command, read_timeout=self.spec.command_timeout
            )
        except Exception as exc:
            raise CommandExecutionError(f"Cisco show command failed '{command}': {exc}") from exc
        finally:
            if self._session_id and self._connected:
                await ssh_session_tracker.mark_idle(self._session_id)

    async def execute_config(self, commands: list[str], save_config: bool = True) -> str:
        if not self._conn:
            raise DeviceConnectionError("Not connected to Cisco device")
        AISafeGuardrails.inspect_commands("execute_config", commands, vendor="cisco_ios")
        summary_cmd = " ; ".join(commands[:3]) + (" ..." if len(commands) > 3 else "")
        if self._session_id:
            await ssh_session_tracker.mark_executing(self._session_id, f"conf t: {summary_cmd}")

        def _apply() -> str:
            output = self._conn.send_config_set(commands)
            if save_config:
                output += "\n" + self._conn.save_config()
            return output

        try:
            return await asyncio.to_thread(_apply)
        except Exception as exc:
            raise CommandExecutionError(f"Cisco config execution failed: {exc}") from exc
        finally:
            if self._session_id and self._connected:
                await ssh_session_tracker.mark_idle(self._session_id)

    async def get_facts(self) -> SwitchFacts:
        ver_out = await self.execute_show("show version")
        stack_out = ""
        if self.spec.is_stacked:
            stack_out = await self.execute_show("show switch")

        hostname_m = re.search(r"^(\S+)\s+uptime\s+is\s+(.+)$", ver_out, re.MULTILINE)
        hostname = hostname_m.group(1) if hostname_m else self.spec.hostname
        uptime_str = hostname_m.group(2) if hostname_m else ""
        os_m = re.search(r"Version\s+([0-9A-Za-z().]+)", ver_out)
        serial_m = re.search(r"System [Ss]erial [Nn]umber\s*:\s*(\S+)", ver_out)
        model_m = re.search(r"[Mm]odel [Nn]umber\s*:\s*(\S+)", ver_out)

        stack_members = self._parse_stack_members(stack_out) if stack_out else []
        return SwitchFacts(
            hostname=hostname,
            vendor="cisco",
            model=model_m.group(1) if model_m else self.spec.model,
            os_version=os_m.group(1) if os_m else "unknown",
            serial_number=serial_m.group(1) if serial_m else "unknown",
            uptime_seconds=self._parse_uptime_seconds(uptime_str),
            is_stacked=self.spec.is_stacked or len(stack_members) > 1,
            stack_members=stack_members,
        )

    async def get_interfaces(self) -> list[InterfaceRecord]:
        raw = await self.execute_show("show interfaces")
        status_raw = await self.execute_show("show interfaces status")
        records: list[InterfaceRecord] = []
        vlan_map: dict[str, tuple[str, str]] = {}

        for line in status_raw.splitlines():
            m = re.match(r"^(\S+)\s+.*?\s+(connected|notconnect|disabled|err-disabled)\s+(\S+)\s+", line)
            if m:
                vlan_map[m.group(1)] = (m.group(2), m.group(3))

        blocks = re.split(r"(?=^[A-Za-z]+\d+[/\d.]*\s+is\s+)", raw, flags=re.MULTILINE)
        for blk in blocks:
            hdr = re.match(r"^(\S+)\s+is\s+(administratively down|up|down),\s+line protocol is\s+(\S+)", blk)
            if not hdr:
                continue
            name = hdr.group(1)
            admin = "down" if "administratively" in hdr.group(2) else "up"
            oper = hdr.group(3).rstrip(",")
            desc_m = re.search(r"Description:\s*(.+)", blk)
            err_m = re.search(r"(\d+)\s+input errors,\s+(\d+)\s+CRC", blk)
            out_m = re.search(r"(\d+)\s+output errors", blk)
            bw_m = re.search(r"BW\s+(\d+)\s+Kbit", blk)
            _, vlan_str = vlan_map.get(name, ("", ""))
            vlan_id = int(vlan_str) if vlan_str.isdigit() else None
            mode = "trunk" if vlan_str.lower() == "trunk" else "access"
            records.append(
                InterfaceRecord(
                    name=name,
                    admin_status=admin,
                    oper_status=oper,
                    description=desc_m.group(1).strip() if desc_m else "",
                    speed_mbps=(int(bw_m.group(1)) // 1000) if bw_m else None,
                    vlan_id=vlan_id,
                    mode=mode,
                    input_errors=int(err_m.group(1)) if err_m else 0,
                    crc_errors=int(err_m.group(2)) if err_m else 0,
                    output_errors=int(out_m.group(1)) if out_m else 0,
                )
            )
        return records

    async def get_vlans(self) -> list[VlanRecord]:
        raw = await self.execute_show("show vlan brief")
        vlans: list[VlanRecord] = []
        current: VlanRecord | None = None
        for line in raw.splitlines():
            m = re.match(r"^(\d{1,4})\s+(\S+)\s+(active|act/unsup|suspended)\s*(.*)$", line)
            if m:
                ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
                current = VlanRecord(
                    vlan_id=int(m.group(1)),
                    name=m.group(2),
                    status=m.group(3),
                    ports=ports,
                )
                vlans.append(current)
            elif current and line.startswith(" " * 20):
                extra_ports = [p.strip() for p in line.split(",") if p.strip()]
                current.ports.extend(extra_ports)
        return vlans

    async def get_neighbors(self) -> list[NeighborRecord]:
        neighbors: list[NeighborRecord] = []
        cdp_raw = await self.execute_show("show cdp neighbors detail")
        for blk in cdp_raw.split("-------------------------"):
            dev_m = re.search(r"Device ID:\s*(\S+)", blk)
            ip_m = re.search(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)", blk)
            plat_m = re.search(r"Platform:\s*([^,\n]+)", blk)
            int_m = re.search(r"Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)", blk)
            if dev_m and int_m:
                neighbors.append(
                    NeighborRecord(
                        local_interface=int_m.group(1),
                        neighbor_device=dev_m.group(1),
                        neighbor_interface=int_m.group(2),
                        protocol="CDP",
                        mgmt_ip=ip_m.group(1) if ip_m else None,
                        platform=plat_m.group(1).strip() if plat_m else None,
                    )
                )
        lldp_raw = await self.execute_show("show lldp neighbors detail")
        for blk in lldp_raw.split("------------------------------------------------"):
            sys_m = re.search(r"System Name:\s*(\S+)", blk)
            loc_m = re.search(r"Local Intf:\s*(\S+)", blk)
            rem_m = re.search(r"Port id:\s*(\S+)", blk)
            if sys_m and loc_m and rem_m:
                neighbors.append(
                    NeighborRecord(
                        local_interface=loc_m.group(1),
                        neighbor_device=sys_m.group(1),
                        neighbor_interface=rem_m.group(1),
                        protocol="LLDP",
                    )
                )
        return neighbors

    async def backup_config(self, config_type: str = "running") -> str:
        cmd = "show running-config" if config_type == "running" else "show startup-config"
        return await self.execute_show(cmd)

    async def restore_config(self, config_text: str, replace: bool = False) -> dict[str, Any]:
        AISafeGuardrails.inspect_commands("restore_config", config_text, vendor="cisco_ios")
        lines = [
            ln for ln in config_text.splitlines()
            if ln.strip() and not ln.strip().startswith("!") and not ln.strip().startswith("Building configuration")
        ]
        output = await self.execute_config(lines, save_config=True)
        return {"applied_lines": len(lines), "replace": replace, "output_preview": output[:500]}

    async def health_check(self) -> HealthMetrics:
        cpu_raw = await self.execute_show("show processes cpu")
        mem_raw = await self.execute_show("show memory statistics")
        env_raw = await self.execute_show("show env all")
        stack_raw = await self.execute_show("show switch") if self.spec.is_stacked else ""

        cpu_m = re.search(
            r"five seconds:\s*(\d+)%/\d+%;\s*one minute:\s*(\d+)%;\s*five minutes:\s*(\d+)%",
            cpu_raw,
        )
        mem_m = re.search(r"Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)", mem_raw)
        temp_m = re.search(r"(\d+)\s*C", env_raw)

        total_mem = int(mem_m.group(1)) if mem_m else 1
        used_mem = int(mem_m.group(2)) if mem_m else 0
        free_mem = int(mem_m.group(3)) if mem_m else 0
        stack_members = self._parse_stack_members(stack_raw) if stack_raw else []
        all_ready = all(m.get("state", "").lower() == "ready" for m in stack_members) if stack_members else True

        return HealthMetrics(
            cpu_5sec_pct=float(cpu_m.group(1)) if cpu_m else 0.0,
            cpu_1min_pct=float(cpu_m.group(2)) if cpu_m else 0.0,
            cpu_5min_pct=float(cpu_m.group(3)) if cpu_m else 0.0,
            memory_used_pct=round((used_mem / max(total_mem, 1)) * 100.0, 2),
            memory_free_bytes=free_mem,
            temperature_celsius=float(temp_m.group(1)) if temp_m else None,
            temperature_status="WARNING" if temp_m and int(temp_m.group(1)) > 65 else "OK",
            stack_status="healthy" if (stack_members and all_ready) else ("degraded" if stack_members else "standalone"),
            stack_members_health=stack_members,
        )

    async def collect_inventory(self) -> list[InventoryItem]:
        raw = await self.execute_show("show inventory")
        tpl_path = _TEMPLATE_DIR / "cisco_ios_show_inventory.textfsm"
        if tpl_path.exists():
            with tpl_path.open("r", encoding="utf-8") as fh:
                fsm = textfsm.TextFSM(fh)
                rows = fsm.ParseText(raw)
                return [
                    InventoryItem(
                        slot=row[0],
                        description=row[1],
                        model=row[2],
                        hardware_revision=row[3],
                        serial_number=row[4],
                    )
                    for row in rows
                ]
        items: list[InventoryItem] = []
        pattern = re.compile(
            r'NAME:\s*"([^"]+)",\s*DESCR:\s*"([^"]+)"\s*\nPID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)'
        )
        for m in pattern.finditer(raw):
            items.append(
                InventoryItem(
                    slot=m.group(1),
                    description=m.group(2),
                    model=m.group(3),
                    hardware_revision=m.group(4),
                    serial_number=m.group(5),
                )
            )
        return items

    async def get_mac_table(self) -> list[dict[str, Any]]:
        raw = await self.execute_show("show mac address-table")
        entries: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = re.match(r"^\s*(\d+|All)\s+([0-9a-fA-F.]{14})\s+(DYNAMIC|STATIC)\s+(\S+)", line)
            if m:
                entries.append({
                    "vlan": m.group(1),
                    "mac_address": m.group(2),
                    "type": m.group(3),
                    "port": m.group(4),
                })
        return entries

    async def get_arp_table(self) -> list[dict[str, Any]]:
        raw = await self.execute_show("show ip arp")
        entries: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = re.match(r"^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-fA-F.]+)\s+ARPA\s+(\S+)", line)
            if m:
                entries.append({
                    "ip_address": m.group(1),
                    "age": m.group(2),
                    "mac_address": m.group(3),
                    "interface": m.group(4),
                })
        return entries

    async def get_logs(self, lines: int = 100) -> list[str]:
        raw = await self.execute_show("show logging")
        all_lines = [ln for ln in raw.splitlines() if ln.strip()]
        return all_lines[-lines:]

    async def get_spanning_tree(self) -> dict[str, Any]:
        raw = await self.execute_show("show spanning-tree summary")
        detail = await self.execute_show("show spanning-tree detail | include Topology|occurred")
        return {"summary": raw, "topology_changes": detail.splitlines()}

    async def run_cable_diagnostics(self, interface: str) -> dict[str, Any]:
        safe_if = AISafeGuardrails.sanitize_interface(interface)
        await self.execute_show(f"test cable-diagnostics tdr interface {safe_if}")
        await asyncio.sleep(2)
        result = await self.execute_show(f"show cable-diagnostics tdr interface {safe_if}")
        return {"interface": safe_if, "raw_tdr": result}

    @staticmethod
    def _parse_stack_members(stack_out: str) -> list[dict[str, Any]]:
        members: list[dict[str, Any]] = []
        for line in stack_out.splitlines():
            m = re.match(r"^\*?\s*(\d+)\s+(Active|Standby|Member)\s+([0-9a-fA-F.]+)\s+(\d+)\s+\S+\s+(\S+)", line)
            if m:
                members.append({
                    "switch_num": int(m.group(1)),
                    "role": m.group(2),
                    "mac_address": m.group(3),
                    "priority": int(m.group(4)),
                    "state": m.group(5),
                })
        return members

    @staticmethod
    def _parse_uptime_seconds(uptime_str: str) -> int:
        total = 0
        for num, unit in re.findall(r"(\d+)\s+(year|week|day|hour|minute)", uptime_str):
            n = int(num)
            if unit == "year":
                total += n * 31536000
            elif unit == "week":
                total += n * 604800
            elif unit == "day":
                total += n * 86400
            elif unit == "hour":
                total += n * 3600
            elif unit == "minute":
                total += n * 60
        return total

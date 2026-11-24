"""ArubaOS-Switch Adapter supporting Aruba 2930F (VSF) and Aruba 2930M (Backplane Stack)."""

import asyncio
import re
from typing import Any

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


class ArubaAdapter(SwitchAdapter):
    """Production adapter for ArubaOS-Switch 2930F and 2930M standalone & stacked devices."""

    SUPPORTED_MODELS = frozenset({
        "Aruba 2930F",
        "Aruba 2930M",
        "JL253A",
        "JL254A",
        "JL320A",
        "JL322A",
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
            vendor="aruba",
            model=self.spec.model,
        )

        def _connect() -> Any:
            import os
            import tempfile

            key_path: str | None = None
            try:
                params: dict[str, Any] = {
                    "device_type": "hp_procurve",
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
                conn.send_command("no page")
                return conn
            finally:
                if key_path and os.path.exists(key_path):
                    os.unlink(key_path)

        try:
            self._conn = await asyncio.to_thread(_connect)
            self._connected = True
            ACTIVE_SSH_SESSIONS.labels(vendor="aruba").inc()
            if self._session_id:
                await ssh_session_tracker.mark_connected(self._session_id)
        except (NetmikoAuthenticationException, NetmikoTimeoutException, OSError) as exc:
            if self._session_id:
                await ssh_session_tracker.end_session(self._session_id, error=str(exc))
                self._session_id = None
            raise DeviceConnectionError(
                f"Failed to connect to Aruba switch {self.spec.hostname} ({self.spec.mgmt_ip}): {exc}"
            ) from exc

    async def disconnect(self) -> None:
        if self._conn is not None:
            try:
                await asyncio.to_thread(self._conn.disconnect)
            finally:
                self._conn = None
                if self._connected:
                    ACTIVE_SSH_SESSIONS.labels(vendor="aruba").dec()
                self._connected = False
        if self._session_id:
            await ssh_session_tracker.end_session(self._session_id)
            self._session_id = None

    async def execute_show(self, command: str) -> str:
        if not self._conn:
            raise DeviceConnectionError("Not connected to Aruba device")
        AISafeGuardrails.inspect_commands("execute_show", command, vendor="aruba_os")
        if self._session_id:
            await ssh_session_tracker.mark_executing(self._session_id, command)
        try:
            return await asyncio.to_thread(
                self._conn.send_command, command, read_timeout=self.spec.command_timeout
            )
        except Exception as exc:
            raise CommandExecutionError(f"Aruba show command failed '{command}': {exc}") from exc
        finally:
            if self._session_id and self._connected:
                await ssh_session_tracker.mark_idle(self._session_id)

    async def execute_config(self, commands: list[str], save_config: bool = True) -> str:
        if not self._conn:
            raise DeviceConnectionError("Not connected to Aruba device")
        AISafeGuardrails.inspect_commands("execute_config", commands, vendor="aruba_os")
        summary_cmd = " ; ".join(commands[:3]) + (" ..." if len(commands) > 3 else "")
        if self._session_id:
            await ssh_session_tracker.mark_executing(self._session_id, f"configure: {summary_cmd}")

        def _apply() -> str:
            output = self._conn.send_config_set(commands)
            if save_config:
                output += "\n" + self._conn.send_command("write memory")
            return output

        try:
            return await asyncio.to_thread(_apply)
        except Exception as exc:
            raise CommandExecutionError(f"Aruba config execution failed: {exc}") from exc
        finally:
            if self._session_id and self._connected:
                await ssh_session_tracker.mark_idle(self._session_id)

    async def get_facts(self) -> SwitchFacts:
        sys_raw = await self.execute_show("show system")
        ver_raw = await self.execute_show("show version")
        stack_members = await self._get_stack_members()

        name_m = re.search(r"System Name\s*:\s*(\S+)", sys_raw)
        os_m = re.search(r"Software revision\s*:\s*(\S+)", sys_raw)
        serial_m = re.search(r"Serial Number\s*:\s*(\S+)", sys_raw)
        uptime_m = re.search(r"Up Time\s*:\s*(.+)", sys_raw)
        model_m = re.search(r"(Aruba\s+\S+|JL\d+A)", ver_raw)

        return SwitchFacts(
            hostname=name_m.group(1) if name_m else self.spec.hostname,
            vendor="aruba",
            model=model_m.group(1) if model_m else self.spec.model,
            os_version=os_m.group(1) if os_m else "unknown",
            serial_number=serial_m.group(1) if serial_m else "unknown",
            uptime_seconds=self._parse_uptime(uptime_m.group(1) if uptime_m else ""),
            is_stacked=self.spec.is_stacked or len(stack_members) > 1,
            stack_members=stack_members,
        )

    async def get_interfaces(self) -> list[InterfaceRecord]:
        brief_raw = await self.execute_show("show interfaces brief")
        records: list[InterfaceRecord] = []
        for line in brief_raw.splitlines():
            m = re.match(
                r"^\s*([0-9/A-Za-z\-]+)\s+\S+\s+(Yes|No)\s+(Up|Down)\s+(\S+)\s+(\S+)",
                line,
            )
            if m:
                records.append(
                    InterfaceRecord(
                        name=m.group(1),
                        admin_status="up" if m.group(2) == "Yes" else "down",
                        oper_status=m.group(3).lower(),
                        mode=m.group(4).lower(),
                        duplex="full" if "FDx" in m.group(5) else "auto",
                    )
                )
        return records

    async def get_vlans(self) -> list[VlanRecord]:
        raw = await self.execute_show("show vlans")
        vlans: list[VlanRecord] = []
        for line in raw.splitlines():
            m = re.match(r"^\s*(\d{1,4})\s+(.+?)\s+(Port-based|Protocol)\s+(Yes|No)", line)
            if m:
                vlans.append(
                    VlanRecord(
                        vlan_id=int(m.group(1)),
                        name=m.group(2).strip(),
                        status="active",
                        ports=[],
                    )
                )
        return vlans

    async def get_neighbors(self) -> list[NeighborRecord]:
        raw = await self.execute_show("show lldp info remote-device")
        neighbors: list[NeighborRecord] = []
        for line in raw.splitlines():
            m = re.match(r"^\s*([0-9/]+)\s+\S+\s+(\S+)\s+(\S+)\s+(.+)$", line)
            if m and not line.strip().startswith("LocalPort"):
                neighbors.append(
                    NeighborRecord(
                        local_interface=m.group(1),
                        neighbor_interface=m.group(2),
                        neighbor_device=m.group(4).strip(),
                        protocol="LLDP",
                    )
                )
        return neighbors

    async def backup_config(self, config_type: str = "running") -> str:
        cmd = "show running-config" if config_type == "running" else "show config"
        return await self.execute_show(cmd)

    async def restore_config(self, config_text: str, replace: bool = False) -> dict[str, Any]:
        AISafeGuardrails.inspect_commands("restore_config", config_text, vendor="aruba_os")
        lines = [
            ln for ln in config_text.splitlines()
            if ln.strip() and not ln.strip().startswith(";")
        ]
        output = await self.execute_config(lines, save_config=True)
        return {"applied_lines": len(lines), "replace": replace, "output_preview": output[:500]}

    async def health_check(self) -> HealthMetrics:
        cpu_raw = await self.execute_show("show cpu")
        mem_raw = await self.execute_show("show system memory")
        temp_raw = await self.execute_show("show system temperature")
        stack_members = await self._get_stack_members()

        cpu_m = re.search(r"(\d+)\s+percent", cpu_raw)
        mem_free_m = re.search(r"Free\s*:\s*([\d,]+)", mem_raw)
        mem_total_m = re.search(r"Total\s*:\s*([\d,]+)", mem_raw)
        temp_m = re.search(r"(\d+)\s*C", temp_raw)

        free_b = int(mem_free_m.group(1).replace(",", "")) if mem_free_m else 0
        total_b = int(mem_total_m.group(1).replace(",", "")) if mem_total_m else 1
        used_pct = round(((total_b - free_b) / max(total_b, 1)) * 100.0, 2)
        cpu_pct = float(cpu_m.group(1)) if cpu_m else 0.0

        return HealthMetrics(
            cpu_5sec_pct=cpu_pct,
            cpu_1min_pct=cpu_pct,
            cpu_5min_pct=cpu_pct,
            memory_used_pct=used_pct,
            memory_free_bytes=free_b,
            temperature_celsius=float(temp_m.group(1)) if temp_m else None,
            temperature_status="WARNING" if temp_m and int(temp_m.group(1)) > 65 else "OK",
            stack_status="healthy" if stack_members else "standalone",
            stack_members_health=stack_members,
        )

    async def collect_inventory(self) -> list[InventoryItem]:
        raw = await self.execute_show("show system information")
        mod_raw = await self.execute_show("show modules")
        items: list[InventoryItem] = []
        serial_m = re.search(r"Serial Number\s*:\s*(\S+)", raw)
        rom_m = re.search(r"ROM Version\s*:\s*(\S+)", raw)
        items.append(
            InventoryItem(
                slot="Chassis",
                model=self.spec.model,
                serial_number=serial_m.group(1) if serial_m else "unknown",
                description=f"{self.spec.model} Switch",
                firmware_version=rom_m.group(1) if rom_m else "",
            )
        )
        for line in mod_raw.splitlines():
            m = re.match(r"^\s*(\d+|Member\s+\d+)\s+(.+?)\s+([A-Z0-9]{8,})\s+(\S+)\s*$", line)
            if m:
                items.append(
                    InventoryItem(
                        slot=m.group(1).strip(),
                        description=m.group(2).strip(),
                        model=self.spec.model,
                        serial_number=m.group(3),
                        firmware_version=m.group(4),
                    )
                )
        return items

    async def get_mac_table(self) -> list[dict[str, Any]]:
        raw = await self.execute_show("show mac-address")
        entries: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F\-]{14,17})\s+(\S+)\s+(\d+)", line)
            if m:
                entries.append({
                    "mac_address": m.group(1),
                    "port": m.group(2),
                    "vlan": m.group(3),
                })
        return entries

    async def get_arp_table(self) -> list[dict[str, Any]]:
        raw = await self.execute_show("show arp")
        entries: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)\s+(\S+)\s+(\S+)", line)
            if m:
                entries.append({
                    "ip_address": m.group(1),
                    "mac_address": m.group(2),
                    "type": m.group(3),
                    "port": m.group(4),
                })
        return entries

    async def get_logs(self, lines: int = 100) -> list[str]:
        raw = await self.execute_show("show logging -r")
        return [ln for ln in raw.splitlines() if ln.strip()][:lines]

    async def get_spanning_tree(self) -> dict[str, Any]:
        raw = await self.execute_show("show spanning-tree")
        return {"summary": raw, "topology_changes": []}

    async def run_cable_diagnostics(self, interface: str) -> dict[str, Any]:
        safe_if = AISafeGuardrails.sanitize_interface(interface)
        raw = await self.execute_show(f"test cable-diagnostics {safe_if}")
        return {"interface": safe_if, "raw_tdr": raw}

    async def _get_stack_members(self) -> list[dict[str, Any]]:
        if not self.spec.is_stacked:
            return []
        cmd = "show vsf" if "2930F" in self.spec.model else "show stacking"
        raw = await self.execute_show(cmd)
        members: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = re.match(r"^\s*(\d+)\s+([0-9a-fA-F\-]+)\s+(Commander|Standby|Member)\s+(\S+)", line)
            if m:
                members.append({
                    "member_id": int(m.group(1)),
                    "mac_address": m.group(2),
                    "role": m.group(3),
                    "state": m.group(4),
                })
        return members

    @staticmethod
    def _parse_uptime(raw: str) -> int:
        m = re.search(r"(\d+)\s+days?", raw)
        return int(m.group(1)) * 86400 if m else 0

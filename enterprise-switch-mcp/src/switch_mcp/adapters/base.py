"""Abstract SwitchAdapter base class and canonical multi-vendor data models."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


class DeviceConnectionSpec(BaseModel):
    device_id: str
    hostname: str
    mgmt_ip: str
    port: int = 22
    vendor: str
    model: str
    is_stacked: bool = False
    stack_count: int = 1
    username: str
    password: str
    enable_secret: str | None = None
    ssh_private_key: str | None = None
    connect_timeout: int = 15
    command_timeout: int = 60


class SwitchFacts(BaseModel):
    hostname: str
    vendor: str
    model: str
    os_version: str
    serial_number: str
    uptime_seconds: int
    is_stacked: bool = False
    stack_members: list[dict[str, Any]] = Field(default_factory=list)


class InterfaceRecord(BaseModel):
    name: str
    admin_status: str
    oper_status: str
    description: str = ""
    speed_mbps: int | None = None
    duplex: str = "auto"
    vlan_id: int | None = None
    mode: str = "access"
    input_errors: int = 0
    output_errors: int = 0
    crc_errors: int = 0


class VlanRecord(BaseModel):
    vlan_id: int
    name: str
    status: str = "active"
    ports: list[str] = Field(default_factory=list)


class NeighborRecord(BaseModel):
    local_interface: str
    neighbor_device: str
    neighbor_interface: str
    protocol: str
    mgmt_ip: str | None = None
    platform: str | None = None


class HealthMetrics(BaseModel):
    cpu_5sec_pct: float
    cpu_1min_pct: float
    cpu_5min_pct: float
    memory_used_pct: float
    memory_free_bytes: int
    temperature_celsius: float | None = None
    temperature_status: str = "OK"
    stack_status: str = "standalone"
    stack_members_health: list[dict[str, Any]] = Field(default_factory=list)


@dataclass
class InventoryItem:
    slot: str
    model: str
    serial_number: str
    description: str
    firmware_version: str = ""
    hardware_revision: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class SwitchAdapter(ABC):
    """Vendor-neutral abstract interface for Cisco IOS & ArubaOS-Switch devices."""

    def __init__(self, spec: DeviceConnectionSpec) -> None:
        self.spec = spec
        self._connected: bool = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    @abstractmethod
    async def connect(self) -> None:
        """Establish authenticated SSH/NAPALM session to the switch."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully close transport sessions."""

    @abstractmethod
    async def get_facts(self) -> SwitchFacts:
        """Collect normalized system identity, OS, serial, uptime, and stack state."""

    @abstractmethod
    async def get_interfaces(self) -> list[InterfaceRecord]:
        """Collect normalized interface status, VLAN, speed, and error counters."""

    @abstractmethod
    async def get_vlans(self) -> list[VlanRecord]:
        """Collect VLAN database entries and assigned ports."""

    @abstractmethod
    async def get_neighbors(self) -> list[NeighborRecord]:
        """Collect LLDP and CDP neighbor topology records."""

    @abstractmethod
    async def backup_config(self, config_type: str = "running") -> str:
        """Retrieve running or startup configuration text."""

    @abstractmethod
    async def restore_config(self, config_text: str, replace: bool = False) -> dict[str, Any]:
        """Apply or replace configuration via atomic merge/replace + rollback guard."""

    @abstractmethod
    async def health_check(self) -> HealthMetrics:
        """Collect CPU, memory, thermal sensors, and stack ring/VSF health."""

    @abstractmethod
    async def execute_show(self, command: str) -> str:
        """Execute a read-only diagnostic show command."""

    @abstractmethod
    async def execute_config(self, commands: list[str], save_config: bool = True) -> str:
        """Execute validated configuration commands after guardrail & approval checks."""

    @abstractmethod
    async def collect_inventory(self) -> list[InventoryItem]:
        """Collect chassis, stack member, PSU, and transceiver serial inventory."""

    # Extended operational primitives implemented per vendor
    @abstractmethod
    async def get_mac_table(self) -> list[dict[str, Any]]:
        """Retrieve MAC address table entries."""

    @abstractmethod
    async def get_arp_table(self) -> list[dict[str, Any]]:
        """Retrieve ARP cache entries."""

    @abstractmethod
    async def get_logs(self, lines: int = 100) -> list[str]:
        """Retrieve buffered syslog entries."""

    @abstractmethod
    async def get_spanning_tree(self) -> dict[str, Any]:
        """Retrieve STP/RSTP root bridge, blocked ports, and topology changes."""

    @abstractmethod
    async def run_cable_diagnostics(self, interface: str) -> dict[str, Any]:
        """Run TDR / cable diagnostics on a copper port."""

    async def __aenter__(self) -> "SwitchAdapter":
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.disconnect()

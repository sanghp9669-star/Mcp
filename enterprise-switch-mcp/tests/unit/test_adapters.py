"""Unit tests for SwitchAdapterFactory, CiscoAdapter, and ArubaAdapter."""

import pytest

from switch_mcp.adapters.aruba_adapter import ArubaAdapter
from switch_mcp.adapters.base import DeviceConnectionSpec
from switch_mcp.adapters.cisco_adapter import CiscoAdapter
from switch_mcp.adapters.factory import SwitchAdapterFactory
from switch_mcp.core.exceptions import ValidationError


def _spec(vendor: str, model: str) -> DeviceConnectionSpec:
    return DeviceConnectionSpec(
        device_id="dev-1",
        hostname="SW-HCM-01",
        mgmt_ip="10.20.0.10",
        vendor=vendor,
        model=model,
        username="netops",
        password="vault-injected-password",
    )


def test_factory_creates_vendor_adapters() -> None:
    cisco = SwitchAdapterFactory.create(_spec("cisco", "Catalyst 2960X"))
    aruba = SwitchAdapterFactory.create(_spec("aruba", "Aruba 2930F"))
    assert isinstance(cisco, CiscoAdapter)
    assert isinstance(aruba, ArubaAdapter)

    with pytest.raises(ValidationError):
        SwitchAdapterFactory.create(_spec("unknown_vendor", "X1"))


from switch_mcp.adapters.session_tracker import SSHSessionTracker


def test_cisco_stack_and_uptime_parsing() -> None:
    sample_stack = """
    Switch/Stack Mac Address : 001e.f7a1.2200
    *1       Active   001e.f7a1.2200     15     V04     Ready
     2       Standby  001e.f7a1.2300     14     V04     Ready
    """
    members = CiscoAdapter._parse_stack_members(sample_stack)
    assert len(members) == 2
    assert members[0]["role"] == "Active"
    assert members[1]["state"] == "Ready"
    assert CiscoAdapter._parse_uptime_seconds("2 weeks, 3 days, 4 hours, 10 minutes") == (
        2 * 604800 + 3 * 86400 + 4 * 3600 + 10 * 60
    )


@pytest.mark.asyncio
async def test_ssh_session_tracker_lifecycle() -> None:
    tracker = SSHSessionTracker()
    events: list[dict] = []

    async def _listener(evt: dict) -> None:
        events.append(evt)

    tracker.subscribe(_listener)
    sid = await tracker.start_session(
        hostname="SW-EDGE-01",
        mgmt_ip="10.20.0.10",
        ssh_port=22,
        vendor="cisco",
        model="Catalyst 2960X",
    )
    await tracker.mark_connected(sid)
    await tracker.mark_executing(sid, "show interfaces status")
    snap = await tracker.snapshot()
    assert len(snap["active_sessions"]) == 1
    assert snap["active_sessions"][0]["status"] == "executing"
    assert snap["active_sessions"][0]["current_command"] == "show interfaces status"

    await tracker.end_session(sid)
    snap_after = await tracker.snapshot()
    assert len(snap_after["active_sessions"]) == 0
    assert len(snap_after["recent_sessions"]) == 1
    assert snap_after["recent_sessions"][0]["status"] == "closed"
    assert [e["type"] for e in events] == ["session:created", "session:updated", "session:updated", "session:closed"]

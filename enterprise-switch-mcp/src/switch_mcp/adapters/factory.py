"""Factory Pattern for instantiating vendor-specific SwitchAdapter instances."""

from switch_mcp.adapters.aruba_adapter import ArubaAdapter
from switch_mcp.adapters.base import DeviceConnectionSpec, SwitchAdapter
from switch_mcp.adapters.cisco_adapter import CiscoAdapter
from switch_mcp.core.exceptions import ValidationError


class SwitchAdapterFactory:
    """Registry-backed Factory producing CiscoAdapter or ArubaAdapter."""

    _REGISTRY: dict[str, type[SwitchAdapter]] = {
        "cisco": CiscoAdapter,
        "cisco_ios": CiscoAdapter,
        "aruba": ArubaAdapter,
        "aruba_os": ArubaAdapter,
    }

    SUPPORTED_HARDWARE: dict[str, list[str]] = {
        "cisco": ["Catalyst 3750CX", "Catalyst 2960", "Catalyst 2960S", "Catalyst 2960X"],
        "aruba": ["Aruba 2930F", "Aruba 2930M"],
    }

    @classmethod
    def create(cls, spec: DeviceConnectionSpec) -> SwitchAdapter:
        vendor_key = spec.vendor.lower().strip()
        adapter_cls = cls._REGISTRY.get(vendor_key)
        if adapter_cls is None:
            raise ValidationError(
                f"Unsupported switch vendor '{spec.vendor}'. Supported: cisco, aruba"
            )
        return adapter_cls(spec)

    @classmethod
    def register(cls, vendor_key: str, adapter_cls: type[SwitchAdapter]) -> None:
        cls._REGISTRY[vendor_key.lower()] = adapter_cls

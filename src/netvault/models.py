"""Shared data models and vocabulary used across netvault modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

# Vendors with a built-in compliance baseline. Canonical names are used
# everywhere (vault rows, rule scopes, report labels).
SUPPORTED_VENDORS: tuple[str, ...] = ("cisco-ios", "aruba")

VENDOR_LABELS: Mapping[str, str] = {
    "cisco-ios": "Cisco IOS",
    "aruba": "Aruba / HP",
}

# Accepted spellings in configuration front matter and in JSON rule files.
VENDOR_ALIASES: Mapping[str, str] = {
    "cisco-ios": "cisco-ios",
    "cisco_ios": "cisco-ios",
    "ciscoios": "cisco-ios",
    "cisco-ios-xe": "cisco-ios",
    "ios": "cisco-ios",
    "ios-xe": "cisco-ios",
    "iosxe": "cisco-ios",
    "cisco": "cisco-ios",
    "aruba": "aruba",
    "arubaos": "aruba",
    "aruba-os": "aruba",
    "arubaos-s": "aruba",
    "arubaos-switch": "aruba",
    "hp": "aruba",
    "hp-aruba": "aruba",
    "procurve": "aruba",
    "hp-procurve": "aruba",
}

# Severity vocabulary and weights used for the weighted compliance score.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
SEVERITY_WEIGHTS: Mapping[str, int] = {"critical": 10, "high": 5, "medium": 3, "low": 1}
SEVERITY_ORDER: Mapping[str, int] = {name: index for index, name in enumerate(SEVERITIES)}

# Compliance finding statuses.
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"
STATUSES: tuple[str, ...] = (STATUS_PASS, STATUS_FAIL, STATUS_SKIP)


def normalize_vendor(value: str) -> str | None:
    """Return the canonical vendor name for *value*, or ``None`` if unknown."""
    return VENDOR_ALIASES.get(value.strip().lower())


def validate_severity(value: str) -> str:
    """Return the normalized severity, raising ``ValueError`` when invalid."""
    severity = value.strip().lower()
    if severity not in SEVERITIES:
        raise ValueError(
            f"invalid severity {value!r}; expected one of: {', '.join(SEVERITIES)}"
        )
    return severity


def validate_vendor(value: str) -> str:
    """Return the canonical vendor, raising ``ValueError`` when unsupported."""
    vendor = normalize_vendor(value)
    if vendor is None:
        raise ValueError(
            f"unsupported vendor {value!r}; expected one of: {', '.join(SUPPORTED_VENDORS)}"
        )
    return vendor


@dataclass(frozen=True)
class DeviceInfo:
    """Metadata identifying one managed network device."""

    name: str
    vendor: str
    site: str = ""
    role: str = ""

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("device name must not be empty")
        vendor = validate_vendor(self.vendor)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "vendor", vendor)
        object.__setattr__(self, "site", self.site.strip())
        object.__setattr__(self, "role", self.role.strip())


@dataclass(frozen=True)
class SnapshotRecord:
    """One immutable revision of a device configuration in the vault."""

    device: str
    vendor: str
    revision: int
    digest: str
    captured_at: str
    note: str
    source_name: str
    size_bytes: int
    line_count: int


@dataclass(frozen=True)
class SnapshotOutcome:
    """Result of storing a snapshot: the record plus whether it was new."""

    record: SnapshotRecord
    created: bool


@dataclass(frozen=True)
class DeviceSummary:
    """Aggregated state of one device as stored in the vault index."""

    name: str
    vendor: str
    site: str
    role: str
    revisions: int
    latest_revision: int
    latest_captured_at: str
    latest_digest: str


@dataclass(frozen=True)
class VaultStats:
    """High-level counters describing a vault."""

    devices: int
    snapshots: int
    blobs: int
    config_bytes: int

"""Directory-based configuration collector.

A collection directory is a tree (nesting is allowed, for example one folder
per site) containing one exported configuration per device with a ``.cfg``,
``.conf`` or ``.txt`` suffix. Metadata can be declared in a header of
``# key: value`` lines at the top of the file::

    # device: core-sw-01
    # vendor: cisco-ios
    # site: porto-lab
    # role: core-switch

The device name falls back to the file stem and the vendor is detected from
configuration markers when the header omits them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import DeviceInfo, normalize_vendor
from .normalize import normalize_config

CONFIG_SUFFIXES: tuple[str, ...] = (".cfg", ".conf", ".txt")

_METADATA_KEYS = frozenset({"device", "vendor", "site", "role"})
_FRONT_MATTER = re.compile(r"^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$")
_DEVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_MIN_VENDOR_SCORE = 2

# Weighted markers used for vendor detection. A configuration needs at least
# two points to be classified, which keeps ambiguous exports out of the vault.
_CISCO_MARKERS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"^version \d+\.\d+", re.MULTILINE), 3),
    (re.compile(r"^service timestamps debug ", re.MULTILINE), 2),
    (re.compile(r"^service timestamps log ", re.MULTILINE), 2),
    (re.compile(r"^boot system ", re.MULTILINE), 2),
    (re.compile(r"^ip cef\s*$", re.MULTILINE), 2),
    (
        re.compile(
            r"^interface (?:GigabitEthernet|FastEthernet|TenGigabitEthernet|Ethernet|Serial|Loopback|Vlan)\S*",
            re.MULTILINE,
        ),
        2,
    ),
    (re.compile(r"^line (?:vty|con|aux) ", re.MULTILINE), 2),
    (re.compile(r"^aaa new-model\s*$", re.MULTILINE), 1),
    (re.compile(r"^spanning-tree (?:mode|extend) ", re.MULTILINE), 1),
    (re.compile(r"^end\s*$", re.MULTILINE), 1),
)

_ARUBA_MARKERS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"Configuration Editor"), 4),
    (re.compile(r"^; Ver #", re.MULTILINE), 3),
    (re.compile(r'^hostname "[^"]+"\s*$', re.MULTILINE), 2),
    (re.compile(r"^module \d+ type ", re.MULTILINE), 2),
    (re.compile(r"^no telnet-server\s*$", re.MULTILINE), 2),
    (re.compile(r"^\s*untagged \d", re.MULTILINE), 2),
    (re.compile(r"^spanning-tree\s*$", re.MULTILINE), 1),
    (re.compile(r"^vlan \d+\s*$", re.MULTILINE), 1),
    (re.compile(r"^\s*tagged \d", re.MULTILINE), 1),
    (re.compile(r"^ip ssh\s*$", re.MULTILINE), 1),
    (re.compile(r"^logging \d+\.\d+", re.MULTILINE), 1),
)


class CollectionError(RuntimeError):
    """Raised when a configuration export cannot be collected safely."""


@dataclass(frozen=True)
class CollectedConfig:
    """One validated configuration export with its device metadata."""

    info: DeviceInfo
    content: str
    source: str


@dataclass(frozen=True)
class CollectionIssue:
    """A problem found while scanning a collection directory."""

    source: str
    message: str


@dataclass(frozen=True)
class CollectionResult:
    """Outcome of scanning a collection directory."""

    configs: tuple[CollectedConfig, ...]
    issues: tuple[CollectionIssue, ...]


def detect_vendor(config: str) -> str | None:
    """Detect the vendor of *config*, returning ``None`` when inconclusive."""
    cisco_score = sum(weight for pattern, weight in _CISCO_MARKERS if pattern.search(config))
    aruba_score = sum(weight for pattern, weight in _ARUBA_MARKERS if pattern.search(config))
    if cisco_score == aruba_score:
        return None
    vendor = "cisco-ios" if cisco_score > aruba_score else "aruba"
    if max(cisco_score, aruba_score) < _MIN_VENDOR_SCORE:
        return None
    return vendor


def _split_front_matter(text: str) -> tuple[dict[str, str], list[str]]:
    """Split leading ``# key: value`` metadata lines from the config body."""
    lines = text.splitlines()
    metadata: dict[str, str] = {}
    body_start = 0
    for index, line in enumerate(lines):
        match = _FRONT_MATTER.match(line)
        if match is None or match.group(1).lower() not in _METADATA_KEYS:
            break
        key = match.group(1).lower()
        if key in metadata:
            raise CollectionError(f"duplicate front matter key {key!r}")
        metadata[key] = match.group(2)
        body_start = index + 1
    return metadata, lines[body_start:]


def parse_config_file(path: str | Path, *, source: str | None = None) -> CollectedConfig:
    """Read and validate one configuration export file.

    Raises:
        CollectionError: when the file cannot be read, has no configuration
            body, has an invalid device name or its vendor cannot be resolved.
    """
    file_path = Path(path)
    display = source or str(file_path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionError(f"not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise CollectionError(f"cannot read file: {exc}") from exc

    metadata, body_lines = _split_front_matter(text)
    body = "\n".join(body_lines)
    if normalize_config(body) == "":
        raise CollectionError("no configuration content found after the header")

    name = metadata.get("device", "").strip() or file_path.stem
    if not _DEVICE_NAME.match(name):
        raise CollectionError(
            f"invalid device name {name!r}; use letters, digits, dots, dashes or underscores"
        )

    vendor_value = metadata.get("vendor", "").strip()
    if vendor_value:
        vendor = normalize_vendor(vendor_value)
        if vendor is None:
            raise CollectionError(
                f"unsupported vendor {vendor_value!r}; expected cisco-ios or aruba"
            )
    else:
        detected = detect_vendor(body)
        if detected is None:
            raise CollectionError(
                "cannot determine the device vendor; add '# vendor: cisco-ios' "
                "or '# vendor: aruba' to the header"
            )
        vendor = detected

    info = DeviceInfo(
        name=name,
        vendor=vendor,
        site=metadata.get("site", ""),
        role=metadata.get("role", ""),
    )
    return CollectedConfig(info=info, content=body, source=display)


def _relative_source(path: Path, root: Path) -> str:
    """Return the path of *path* relative to *root* using POSIX separators."""
    return path.relative_to(root).as_posix()


def _is_hidden(relative: Path) -> bool:
    """Return ``True`` when any part of *relative* starts with a dot."""
    return any(part.startswith(".") for part in relative.parts)


def collect_directory(root: str | Path) -> CollectionResult:
    """Scan *root* recursively and collect every supported configuration file.

    Files are processed in sorted order so results are deterministic. Per-file
    problems are reported as :class:`CollectionIssue` entries instead of
    aborting the whole scan; duplicate device names are reported and skipped.
    """
    root_path = Path(root)
    if not root_path.is_dir():
        raise CollectionError(f"configuration directory not found: {root_path}")

    candidates: list[tuple[Path, str]] = []
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root_path)
        if _is_hidden(relative):
            continue
        if path.suffix.lower() not in CONFIG_SUFFIXES:
            continue
        candidates.append((path, _relative_source(path, root_path)))
    candidates.sort(key=lambda item: item[1].lower())

    configs: list[CollectedConfig] = []
    issues: list[CollectionIssue] = []
    seen_devices: dict[str, str] = {}
    for path, source in candidates:
        try:
            config = parse_config_file(path, source=source)
        except CollectionError as exc:
            issues.append(CollectionIssue(source=source, message=str(exc)))
            continue
        key = config.info.name.lower()
        if key in seen_devices:
            issues.append(
                CollectionIssue(
                    source=source,
                    message=(
                        f"duplicate device name {config.info.name!r}; already collected "
                        f"from {seen_devices[key]!r}"
                    ),
                )
            )
            continue
        seen_devices[key] = source
        configs.append(config)
    return CollectionResult(configs=tuple(configs), issues=tuple(issues))

"""Configuration diffing: unified output plus a semantic change summary.

The unified diff answers "what changed"; the semantic summary answers "what
does an operator need to know for the change ticket": which interfaces were
added, removed or modified, how many ACL and routing lines moved, and how the
configuration size evolved.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

_INTERFACE_HEADER = re.compile(r"^interface\s+(\S+)\s*$")

_ACL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"^ip access-list\b",
        r"^ipv6 access-list\b",
        r"^access-list\b",
        r"^mac access-list\b",
        r"^permit\s+",
        r"^deny\s+",
        r"^\d{1,4}\s+(?:permit|deny)\s+",
    )
)

_ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"^(?:ip|ipv6) route\b",
        r"^ip default-gateway\b",
        r"^ipv6 default-gateway\b",
    )
)


@dataclass(frozen=True)
class InterfaceChanges:
    """Interface blocks added, removed and modified between two revisions."""

    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()


@dataclass(frozen=True)
class SemanticDiff:
    """Operator-oriented summary of a change between two revisions."""

    device: str
    from_revision: int
    to_revision: int
    from_digest: str
    to_digest: str
    from_captured_at: str
    to_captured_at: str
    lines_added: int
    lines_removed: int
    size_delta: int
    line_count_delta: int
    interfaces: InterfaceChanges
    acl_lines_added: int
    acl_lines_removed: int
    route_lines_added: int
    route_lines_removed: int

    @property
    def changed(self) -> bool:
        """Whether anything changed between the two revisions."""
        return bool(
            self.lines_added
            or self.lines_removed
            or self.interfaces.added
            or self.interfaces.removed
            or self.interfaces.modified
        )

    def render_text(self) -> str:
        """Render the summary as a compact text block for a change ticket."""
        if not self.changed:
            return (
                f"No changes between revision {self.from_revision} "
                f"and revision {self.to_revision}."
            )
        return "\n".join(
            (
                f"Change summary - {self.device} "
                f"(revision {self.from_revision} -> {self.to_revision})",
                f"  lines: +{self.lines_added} / -{self.lines_removed} "
                f"(net {self.line_count_delta:+d})",
                f"  size: {self.size_delta:+d} bytes",
                f"  interfaces added: {_names(self.interfaces.added)}",
                f"  interfaces removed: {_names(self.interfaces.removed)}",
                f"  interfaces modified: {_names(self.interfaces.modified)}",
                f"  ACL lines: +{self.acl_lines_added} / -{self.acl_lines_removed}",
                f"  route lines: +{self.route_lines_added} / -{self.route_lines_removed}",
            )
        )


@dataclass(frozen=True)
class DiffResult:
    """Unified diff text plus its semantic summary."""

    summary: SemanticDiff
    unified: str


def _names(values: tuple[str, ...]) -> str:
    """Render a tuple of interface names for text output."""
    return ", ".join(values) if values else "none"


def extract_interfaces(config: str) -> dict[str, str]:
    """Return interface block texts keyed by interface name.

    A block starts at a top-level ``interface <name>`` line and owns the
    following indented lines. Comment separators and top-level commands end the
    block and are not part of its text.
    """
    blocks: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []

    def flush() -> None:
        nonlocal current_name, current_lines
        if current_name is not None:
            while current_lines and (
                not current_lines[-1].strip() or current_lines[-1].strip() == "!"
            ):
                current_lines.pop()
            blocks[current_name] = "\n".join(current_lines)
        current_name = None
        current_lines = []

    for line in config.splitlines():
        header = _INTERFACE_HEADER.match(line)
        if header is not None:
            flush()
            current_name = header.group(1)
            current_lines = [line.rstrip()]
            continue
        if current_name is None:
            continue
        if line.startswith((" ", "\t")):
            current_lines.append(line.rstrip())
            continue
        flush()
    flush()
    return blocks


def _classify_line(line: str) -> str:
    """Classify a changed line as ``acl``, ``route`` or ``other``."""
    stripped = line.strip()
    for pattern in _ACL_PATTERNS:
        if pattern.search(stripped):
            return "acl"
    for pattern in _ROUTE_PATTERNS:
        if pattern.search(stripped):
            return "route"
    return "other"


def _label(device: str, revision: int, captured_at: str, digest: str) -> str:
    """Build a unified-diff file label for one revision."""
    label = f"{device} revision {revision}"
    if captured_at:
        label += f" ({captured_at})"
    if digest:
        label += f" digest {digest[:12]}"
    return label


def unified_diff_text(
    old: str,
    new: str,
    *,
    device: str,
    from_revision: int,
    to_revision: int,
    from_digest: str = "",
    to_digest: str = "",
    from_captured_at: str = "",
    to_captured_at: str = "",
    context: int = 3,
) -> str:
    """Return the unified diff between two configuration texts."""
    lines = difflib.unified_diff(
        old.splitlines(),
        new.splitlines(),
        fromfile=_label(device, from_revision, from_captured_at, from_digest),
        tofile=_label(device, to_revision, to_captured_at, to_digest),
        lineterm="",
        n=context,
    )
    return "\n".join(lines)


def build_diff(
    *,
    device: str,
    old_text: str,
    new_text: str,
    from_revision: int,
    to_revision: int,
    from_digest: str = "",
    to_digest: str = "",
    from_captured_at: str = "",
    to_captured_at: str = "",
    context: int = 3,
) -> DiffResult:
    """Build a unified diff and semantic summary between two configurations."""
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    old_interfaces = extract_interfaces(old_text)
    new_interfaces = extract_interfaces(new_text)

    interface_changes = InterfaceChanges(
        added=tuple(sorted(set(new_interfaces) - set(old_interfaces))),
        removed=tuple(sorted(set(old_interfaces) - set(new_interfaces))),
        modified=tuple(
            sorted(
                name
                for name in set(old_interfaces) & set(new_interfaces)
                if old_interfaces[name] != new_interfaces[name]
            )
        ),
    )

    lines_added = 0
    lines_removed = 0
    acl_added = acl_removed = 0
    route_added = route_removed = 0
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            for line in old_lines[old_start:old_end]:
                lines_removed += 1
                kind = _classify_line(line)
                if kind == "acl":
                    acl_removed += 1
                elif kind == "route":
                    route_removed += 1
        if tag in ("replace", "insert"):
            for line in new_lines[new_start:new_end]:
                lines_added += 1
                kind = _classify_line(line)
                if kind == "acl":
                    acl_added += 1
                elif kind == "route":
                    route_added += 1

    summary = SemanticDiff(
        device=device,
        from_revision=from_revision,
        to_revision=to_revision,
        from_digest=from_digest,
        to_digest=to_digest,
        from_captured_at=from_captured_at,
        to_captured_at=to_captured_at,
        lines_added=lines_added,
        lines_removed=lines_removed,
        size_delta=len(new_text.encode("utf-8")) - len(old_text.encode("utf-8")),
        line_count_delta=len(new_lines) - len(old_lines),
        interfaces=interface_changes,
        acl_lines_added=acl_added,
        acl_lines_removed=acl_removed,
        route_lines_added=route_added,
        route_lines_removed=route_removed,
    )
    unified = unified_diff_text(
        old_text,
        new_text,
        device=device,
        from_revision=from_revision,
        to_revision=to_revision,
        from_digest=from_digest,
        to_digest=to_digest,
        from_captured_at=from_captured_at,
        to_captured_at=to_captured_at,
        context=context,
    )
    return DiffResult(summary=summary, unified=unified)

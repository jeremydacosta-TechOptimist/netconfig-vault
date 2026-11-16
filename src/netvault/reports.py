"""Text, Markdown and standalone HTML report rendering.

Reports are rendered from the in-memory audit and diff models, so the same
data can be printed on the console, written to a change ticket as Markdown, or
published as a self-contained HTML file with no external assets.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Sequence

from .compliance import AuditReport, audit_vault
from .diffing import DiffResult, InterfaceChanges, SemanticDiff, build_diff
from .models import VENDOR_LABELS, DeviceSummary, VaultStats
from .rules import Rule
from .store import Vault, utc_now_iso

_TABLE_SEPARATOR = "  "


# ---------------------------------------------------------------------------
# Small shared formatting helpers
# ---------------------------------------------------------------------------


def _esc(value: object) -> str:
    """HTML-escape a value rendered into a report."""
    return html.escape(str(value))


def _md_cell(value: object) -> str:
    """Render one Markdown table cell, escaping pipes and newlines."""
    text = str(value).replace("|", "\\|").replace("\n", " ").strip()
    return text or "-"


def _vendor_label(vendor: str) -> str:
    """Return the display label for a vendor identifier."""
    return VENDOR_LABELS.get(vendor, vendor)


def _joined_names(values: Sequence[str]) -> str:
    """Render a sequence of interface names, or ``none`` when empty."""
    return ", ".join(values) if values else "none"


def _status_css(status: str) -> str:
    """Return the CSS class used for a finding status."""
    return f"status-{status.lower()}"


def _severity_css(severity: str) -> str:
    """Return the CSS class used for a finding severity."""
    return f"severity-{severity.lower()}"


def _overall_status_text(report: AuditReport) -> str:
    """Render the pass/fail headline with a breakdown of failing severities."""
    if report.total_failed == 0:
        return f"PASS - {report.total_passed} check(s) passed"
    breakdown = ", ".join(
        f"{count} {severity}"
        for severity, count in report.failures_by_severity.items()
        if count
    )
    return f"FAIL - {breakdown} failure(s)"


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    """Render a plain-text table with aligned columns."""
    width = len(headers)
    normalized: list[tuple[str, ...]] = []
    for row in rows:
        cells = tuple(str(cell) for cell in row)
        if len(cells) != width:
            raise ValueError(f"table row has {len(cells)} cells, expected {width}")
        normalized.append(cells)
    widths = [len(header) for header in headers]
    for row in normalized:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def join(cells: Sequence[str]) -> str:
        return _TABLE_SEPARATOR.join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    lines = [join(headers), join(["-" * item for item in widths])]
    lines.extend(join(row) for row in normalized)
    return "\n".join(lines)


def _markdown_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """Render a GitHub-flavoured Markdown table."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_md_cell(cell) for cell in row) + " |")
    return "\n".join(lines)


def _html_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    classes: Sequence[Sequence[str]] | None = None,
) -> str:
    """Render an HTML table with optional per-cell CSS classes."""
    width = len(headers)
    lines = ["<table>", "<thead><tr>"]
    lines.extend(f"<th>{_esc(header)}</th>" for header in headers)
    lines.append("</tr></thead>")
    lines.append("<tbody>")
    for row_index, row in enumerate(rows):
        if len(row) != width:
            raise ValueError(f"table row has {len(row)} cells, expected {width}")
        row_classes = (
            list(classes[row_index])
            if classes is not None
            else ["" for _ in range(width)]
        )
        cells: list[str] = []
        for column, cell in enumerate(row):
            css = row_classes[column] if column < len(row_classes) else ""
            attribute = f' class="{css}"' if css else ""
            cells.append(f"<td{attribute}>{_esc(cell)}</td>")
        lines.append("<tr>" + "".join(cells) + "</tr>")
    lines.append("</tbody>")
    lines.append("</table>")
    return "\n".join(lines)


_STYLE = """
:root { color-scheme: light; }
body {
  margin: 0;
  padding: 32px 16px;
  background: #f5f7fa;
  color: #1f2933;
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 15px;
  line-height: 1.5;
}
main { max-width: 1080px; margin: 0 auto; background: #ffffff; padding: 32px; border: 1px solid #d9e2ec; border-radius: 8px; }
h1 { margin: 0 0 0.5rem; font-size: 1.6rem; }
h2 { margin-top: 2rem; font-size: 1.2rem; border-bottom: 1px solid #d9e2ec; padding-bottom: 0.3rem; }
h3 { margin-top: 1.5rem; font-size: 1.05rem; }
ul.meta { list-style: none; padding: 0; margin: 0 0 1rem; color: #52606d; }
ul.meta li { margin: 0.1rem 0; }
table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.5rem; background: #ffffff; }
th, td { border: 1px solid #d9e2ec; padding: 6px 10px; text-align: left; vertical-align: top; font-size: 0.9rem; }
th { background: #eef2f7; font-weight: 600; }
td.num { text-align: right; }
.status-pass { color: #1b6e3c; font-weight: 600; }
.status-fail { color: #a61b1b; font-weight: 600; }
.status-skip { color: #6b7280; font-weight: 600; }
.severity-critical { color: #7f1d1d; font-weight: 600; }
.severity-high { color: #b45309; font-weight: 600; }
.severity-medium { color: #6d5d00; font-weight: 600; }
.severity-low { color: #52606d; }
.muted { color: #6b7280; font-weight: normal; }
.all-clear { color: #1b6e3c; font-weight: 600; }
pre.diff { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; line-height: 1.45; }
pre.diff span { display: block; white-space: pre; }
.diff-add { color: #7ee787; }
.diff-del { color: #ffa198; }
.diff-hunk { color: #79c0ff; }
.diff-file { color: #d2a8ff; font-weight: 600; }
.diff-ctx { color: #c9d1d9; }
footer { max-width: 1080px; margin: 16px auto 0; color: #6b7280; font-size: 0.8rem; text-align: right; }
"""


def _html_document(title: str, body: str) -> str:
    """Wrap *body* in a standalone HTML document with inline styling."""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n<style>{_STYLE}</style>\n</head>\n"
        f"<body>\n<main>\n{body}\n</main>\n"
        "<footer>Generated by netvault</footer>\n"
        "</body>\n</html>\n"
    )


def _group_failures(report: AuditReport) -> list[tuple[str, str, str, str, list[str]]]:
    """Group failing checks by rule, preserving first-seen order."""
    grouped: dict[str, tuple[str, str, str, list[str]]] = {}
    for audit in report.device_audits:
        for finding in audit.failures:
            entry = grouped.get(finding.rule_id)
            if entry is None:
                grouped[finding.rule_id] = (
                    finding.title,
                    finding.severity,
                    finding.remediation,
                    [audit.device.name],
                )
            else:
                entry[3].append(audit.device.name)
    return [
        (rule_id, title, severity, remediation, devices)
        for rule_id, (title, severity, remediation, devices) in grouped.items()
    ]


# ---------------------------------------------------------------------------
# Compliance audit reports
# ---------------------------------------------------------------------------


def render_audit_text(report: AuditReport) -> str:
    """Render a compact compliance audit summary for the console."""
    lines = [
        f"Compliance audit - {len(report.device_audits)} device(s), "
        f"{report.rule_definitions} rule definition(s) "
        f"({report.builtin_rule_count} built-in, {report.custom_rule_count} custom)",
        f"overall: {_overall_status_text(report)}",
        f"weighted score: {report.overall_weighted_score:.1f}%",
    ]
    if not report.device_audits:
        lines.extend(("", "No devices in the vault were audited."))
        return "\n".join(lines)
    for audit in report.device_audits:
        lines.append("")
        lines.append(
            f"{audit.device.name} ({_vendor_label(audit.device.vendor)}, "
            f"rev {audit.revision}): score {audit.weighted_score:.1f}% "
            f"({audit.passed} pass, {audit.failed} fail, {audit.skipped} skip)"
        )
        for finding in audit.failures:
            lines.append(
                f"  FAIL {finding.severity:<8} {finding.rule_id:<20} {finding.title}"
            )
    lines.extend(
        (
            "",
            f"Summary: {report.total_passed} pass, {report.total_failed} fail, "
            f"{report.total_skipped} skip",
        )
    )
    return "\n".join(lines)


def render_audit_markdown(report: AuditReport) -> str:
    """Render the compliance audit as a Markdown report."""
    lines = [
        "# Compliance audit",
        "",
        f"- Generated: {report.generated_at}",
        f"- Vault: {report.vault_path}",
        f"- Rules: {report.builtin_rule_count} built-in + {report.custom_rule_count} "
        f"custom ({report.rule_definitions} definitions)",
        f"- Devices audited: {len(report.device_audits)}",
        f"- Result: {_overall_status_text(report)}",
        f"- Weighted score: {report.overall_weighted_score:.1f}%",
        "",
        "## Summary",
        "",
    ]
    summary_rows = [
        [
            audit.device.name,
            _vendor_label(audit.device.vendor),
            audit.device.site or "-",
            str(audit.revision),
            f"{audit.weighted_score:.1f}%",
            str(audit.passed),
            str(audit.failed),
            str(audit.skipped),
            str(audit.critical_failures),
        ]
        for audit in report.device_audits
    ]
    if summary_rows:
        lines.append(
            _markdown_table(
                [
                    "Device",
                    "Vendor",
                    "Site",
                    "Revision",
                    "Score",
                    "Passed",
                    "Failed",
                    "Skipped",
                    "Critical",
                ],
                summary_rows,
            )
        )
    else:
        lines.append("No devices in the vault were audited.")
    lines.extend(("", "## Findings", ""))
    for audit in report.device_audits:
        lines.append(
            f"### {_md_cell(audit.device.name)} "
            f"({_vendor_label(audit.device.vendor)}, revision {audit.revision})"
        )
        lines.append("")
        lines.append(
            _markdown_table(
                ["Status", "Severity", "Rule", "Title", "Details"],
                [
                    [
                        finding.status,
                        finding.severity,
                        finding.rule_id,
                        finding.title,
                        "; ".join(finding.details) if finding.details else "-",
                    ]
                    for finding in audit.findings
                ],
            )
        )
        lines.append("")
    failures = _group_failures(report)
    lines.extend(("## Remediation", ""))
    if failures:
        for rule_id, title, severity, remediation, devices in failures:
            guidance = remediation or f"fix {title.lower()}"
            lines.append(
                f"- **{rule_id}** ({severity}, {', '.join(devices)}): {guidance}"
            )
    else:
        lines.append("No failing checks.")
    lines.append("")
    return "\n".join(lines)


def render_audit_html(report: AuditReport) -> str:
    """Render the compliance audit as a standalone HTML document."""
    parts = [
        "<h1>Compliance audit</h1>",
        '<ul class="meta">',
        f"<li>Generated: {_esc(report.generated_at)}</li>",
        f"<li>Vault: {_esc(report.vault_path)}</li>",
        f"<li>Rules: {report.builtin_rule_count} built-in + "
        f"{report.custom_rule_count} custom ({report.rule_definitions} definitions)</li>",
        f"<li>Devices audited: {len(report.device_audits)}</li>",
        f"<li>Result: {_esc(_overall_status_text(report))}</li>",
        f"<li>Weighted score: {report.overall_weighted_score:.1f}%</li>",
        "</ul>",
        "<h2>Summary</h2>",
    ]
    summary_rows: list[list[object]] = []
    summary_classes: list[list[str]] = []
    for audit in report.device_audits:
        summary_rows.append(
            [
                audit.device.name,
                _vendor_label(audit.device.vendor),
                audit.device.site or "-",
                audit.revision,
                f"{audit.weighted_score:.1f}%",
                audit.passed,
                audit.failed,
                audit.skipped,
                audit.critical_failures,
            ]
        )
        summary_classes.append(
            [
                "",
                "",
                "",
                "",
                "",
                "",
                "status-fail" if audit.failed else "status-pass",
                "",
                "severity-critical" if audit.critical_failures else "",
            ]
        )
    if summary_rows:
        parts.append(
            _html_table(
                [
                    "Device",
                    "Vendor",
                    "Site",
                    "Revision",
                    "Score",
                    "Passed",
                    "Failed",
                    "Skipped",
                    "Critical",
                ],
                summary_rows,
                summary_classes,
            )
        )
    else:
        parts.append("<p>No devices in the vault were audited.</p>")

    parts.append("<h2>Findings</h2>")
    for audit in report.device_audits:
        parts.append(
            f'<h3>{_esc(audit.device.name)} '
            f'<span class="muted">({_esc(_vendor_label(audit.device.vendor))}, '
            f"revision {audit.revision})</span></h3>"
        )
        finding_rows: list[list[object]] = []
        finding_classes: list[list[str]] = []
        for finding in audit.findings:
            finding_rows.append(
                [
                    finding.status,
                    finding.severity,
                    finding.rule_id,
                    finding.title,
                    "; ".join(finding.details) if finding.details else "-",
                ]
            )
            finding_classes.append(
                [
                    _status_css(finding.status),
                    _severity_css(finding.severity),
                    "",
                    "",
                    "",
                ]
            )
        parts.append(
            _html_table(
                ["Status", "Severity", "Rule", "Title", "Details"],
                finding_rows,
                finding_classes,
            )
        )

    parts.append("<h2>Remediation</h2>")
    failures = _group_failures(report)
    if failures:
        remediation_rows = [
            [rule_id, severity, ", ".join(devices), remediation or f"fix {title.lower()}"]
            for rule_id, title, severity, remediation, devices in failures
        ]
        remediation_classes = [
            ["", _severity_css(severity), "", ""] for _, _, severity, _, _ in failures
        ]
        parts.append(
            _html_table(
                ["Rule", "Severity", "Devices", "Guidance"],
                remediation_rows,
                remediation_classes,
            )
        )
    else:
        parts.append('<p class="all-clear">No failing checks.</p>')
    return _html_document("netvault compliance audit", "\n".join(parts))


# ---------------------------------------------------------------------------
# Change reports
# ---------------------------------------------------------------------------


def render_diff_text(result: DiffResult) -> str:
    """Render a change report for the console: summary plus unified diff."""
    parts = [result.summary.render_text()]
    if result.unified:
        parts.extend(("", result.unified))
    return "\n".join(parts)


def _diff_meta_lines(summary: SemanticDiff) -> list[tuple[str, str]]:
    """Return the label/value pairs shown at the top of a change report."""
    return [
        ("From revision", f"{summary.from_revision} ({summary.from_captured_at or 'unknown'})"),
        ("To revision", f"{summary.to_revision} ({summary.to_captured_at or 'unknown'})"),
        ("From digest", summary.from_digest or "unknown"),
        ("To digest", summary.to_digest or "unknown"),
        ("Lines added", str(summary.lines_added)),
        ("Lines removed", str(summary.lines_removed)),
        ("Size delta", f"{summary.size_delta:+d} bytes"),
        ("Interfaces added", _joined_names(summary.interfaces.added)),
        ("Interfaces removed", _joined_names(summary.interfaces.removed)),
        ("Interfaces modified", _joined_names(summary.interfaces.modified)),
        ("ACL lines added", str(summary.acl_lines_added)),
        ("ACL lines removed", str(summary.acl_lines_removed)),
        ("Route lines added", str(summary.route_lines_added)),
        ("Route lines removed", str(summary.route_lines_removed)),
    ]


def render_diff_markdown(result: DiffResult, *, include_diff: bool = True) -> str:
    """Render the change report as a Markdown document.

    Args:
        result: Diff result to render.
        include_diff: When false, only the semantic summary is rendered, which
            is useful for a change ticket or pull request description.
    """
    summary = result.summary
    lines = [f"# Change report - {summary.device}", ""]
    lines.extend(f"- {label}: {value}" for label, value in _diff_meta_lines(summary))
    if summary.changed and result.unified and include_diff:
        fence = "~~~~" if "```" in result.unified else "```"
        lines.extend(("", "## Unified diff", "", f"{fence}diff", result.unified, fence, ""))
    elif not summary.changed:
        lines.extend(("", "No changes between the two revisions.", ""))
    return "\n".join(lines)


def _render_unified_html(unified: str) -> str:
    """Wrap unified diff lines in colour-coded HTML spans."""
    rendered: list[str] = []
    for line in unified.splitlines():
        if line.startswith(("+++", "---")):
            css = "diff-file"
        elif line.startswith("@@"):
            css = "diff-hunk"
        elif line.startswith("+"):
            css = "diff-add"
        elif line.startswith("-"):
            css = "diff-del"
        else:
            css = "diff-ctx"
        rendered.append(f'<span class="{css}">{_esc(line)}</span>')
    return "\n".join(rendered)


def render_diff_html(result: DiffResult, *, include_diff: bool = True) -> str:
    """Render the change report as a standalone HTML document.

    Args:
        result: Diff result to render.
        include_diff: When false, only the semantic summary is rendered.
    """
    summary = result.summary
    parts = [
        f"<h1>Change report - {_esc(summary.device)}</h1>",
        '<ul class="meta">',
    ]
    parts.extend(f"<li>{_esc(label)}: {_esc(value)}</li>" for label, value in _diff_meta_lines(summary))
    parts.append("</ul>")
    if summary.changed and result.unified and include_diff:
        parts.append("<h2>Unified diff</h2>")
        parts.append(f'<pre class="diff">{_render_unified_html(result.unified)}</pre>')
    elif not summary.changed:
        parts.append('<p class="all-clear">No changes between the two revisions.</p>')
    return _html_document(f"netvault change report - {summary.device}", "\n".join(parts))


# ---------------------------------------------------------------------------
# Estate report
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EstateChange:
    """The most recent revision transition for one device."""

    device: str
    from_revision: int
    to_revision: int
    captured_at: str
    summary: SemanticDiff


@dataclass(frozen=True)
class EstateReport:
    """Whole-vault inventory, recent changes and compliance snapshot."""

    vault_path: str
    generated_at: str
    stats: VaultStats
    devices: tuple[DeviceSummary, ...]
    changes: tuple[EstateChange, ...]
    audit: AuditReport


def build_estate_report(
    vault: Vault,
    *,
    rules: Sequence[Rule] | None = None,
    generated_at: str | None = None,
) -> EstateReport:
    """Collect inventory, recent changes and compliance state from *vault*."""
    timestamp = generated_at or utc_now_iso()
    audit = audit_vault(vault, rules=rules, generated_at=timestamp)
    stats = vault.stats()
    devices = tuple(vault.list_devices())
    changes: list[EstateChange] = []
    for summary in devices:
        if summary.revisions < 2:
            continue
        old, new = summary.latest_revision - 1, summary.latest_revision
        old_record, old_text = vault.read_revision(summary.name, old)
        new_record, new_text = vault.read_revision(summary.name, new)
        result = build_diff(
            device=summary.name,
            old_text=old_text,
            new_text=new_text,
            from_revision=old_record.revision,
            to_revision=new_record.revision,
            from_digest=old_record.digest,
            to_digest=new_record.digest,
            from_captured_at=old_record.captured_at,
            to_captured_at=new_record.captured_at,
        )
        changes.append(
            EstateChange(
                device=summary.name,
                from_revision=old_record.revision,
                to_revision=new_record.revision,
                captured_at=new_record.captured_at,
                summary=result.summary,
            )
        )
    return EstateReport(
        vault_path=vault.display_path,
        generated_at=timestamp,
        stats=stats,
        devices=devices,
        changes=tuple(changes),
        audit=audit,
    )


def _interface_change_text(interfaces: InterfaceChanges) -> str:
    """Render interface changes as one compact line."""
    parts: list[str] = []
    if interfaces.added:
        parts.append("added: " + ", ".join(interfaces.added))
    if interfaces.removed:
        parts.append("removed: " + ", ".join(interfaces.removed))
    if interfaces.modified:
        parts.append("modified: " + ", ".join(interfaces.modified))
    return "; ".join(parts) if parts else "none"


def _estate_compliance_line(report: EstateReport) -> str:
    """Render the compliance summary line used across estate formats."""
    return _overall_status_text(report.audit)


def _estate_summary_pairs(report: EstateReport) -> list[tuple[str, str]]:
    """Return the label/value pairs shared by all estate report formats."""
    stats = report.stats
    return [
        ("Generated", report.generated_at),
        ("Vault", report.vault_path),
        (
            "Rules",
            f"{report.audit.builtin_rule_count} built-in + "
            f"{report.audit.custom_rule_count} custom",
        ),
        ("Devices", str(stats.devices)),
        ("Snapshots", str(stats.snapshots)),
        ("Unique blobs", str(stats.blobs)),
        ("Stored configuration bytes", str(stats.config_bytes)),
        ("Compliance", _estate_compliance_line(report)),
    ]


def _estate_score(report: EstateReport, device_name: str) -> str:
    """Return the compliance score of one device, or ``-`` when not audited."""
    for audit in report.audit.device_audits:
        if audit.device.name.lower() == device_name.lower():
            return f"{audit.weighted_score:.1f}%"
    return "-"


def render_estate_text(report: EstateReport) -> str:
    """Render the estate report for the console."""
    lines = [
        "netvault estate report",
        f"generated: {report.generated_at}",
        f"vault: {report.vault_path}",
        f"rules: {report.audit.builtin_rule_count} built-in, "
        f"{report.audit.custom_rule_count} custom",
        "",
        "Estate summary",
    ]
    stats = report.stats
    summary_pairs = [
        ("devices", str(stats.devices)),
        ("snapshots", str(stats.snapshots)),
        ("unique blobs", str(stats.blobs)),
        ("stored configuration bytes", str(stats.config_bytes)),
        ("compliance", _estate_compliance_line(report)),
    ]
    width = max(len(label) for label, _ in summary_pairs) + 2
    lines.extend(f"  {label:<{width}}{value}" for label, value in summary_pairs)
    lines.extend(("", "Device inventory"))
    inventory_rows = [
        [
            summary.name,
            _vendor_label(summary.vendor),
            summary.site or "-",
            str(summary.revisions),
            str(summary.latest_revision),
            summary.latest_captured_at or "-",
            _estate_score(report, summary.name),
        ]
        for summary in report.devices
    ]
    lines.append(
        render_table(
            ["Device", "Vendor", "Site", "Revisions", "Latest", "Last snapshot", "Score"],
            inventory_rows,
        )
    )
    lines.extend(("", "Recent changes"))
    if not report.changes:
        lines.append("No device has more than one revision yet.")
    else:
        change_rows = [
            [
                change.device,
                f"{change.from_revision} -> {change.to_revision}",
                change.captured_at,
                f"+{change.summary.lines_added} / -{change.summary.lines_removed}",
                _interface_change_text(change.summary.interfaces),
            ]
            for change in report.changes
        ]
        lines.append(
            render_table(
                ["Device", "Change", "Captured", "Lines", "Interfaces"],
                change_rows,
            )
        )
    return "\n".join(lines)


def render_estate_markdown(report: EstateReport) -> str:
    """Render the estate report as a Markdown document."""
    lines = ["# netvault estate report", ""]
    lines.extend(f"- {label}: {value}" for label, value in _estate_summary_pairs(report))
    lines.extend(("", "## Device inventory", ""))
    lines.append(
        _markdown_table(
            ["Device", "Vendor", "Site", "Revisions", "Latest revision", "Last snapshot", "Compliance score"],
            [
                [
                    summary.name,
                    _vendor_label(summary.vendor),
                    summary.site or "-",
                    summary.revisions,
                    summary.latest_revision,
                    summary.latest_captured_at or "-",
                    _estate_score(report, summary.name),
                ]
                for summary in report.devices
            ],
        )
    )
    lines.extend(("", "## Recent changes", ""))
    if report.changes:
        lines.append(
            _markdown_table(
                ["Device", "Change", "Captured", "Lines added", "Lines removed", "Interfaces"],
                [
                    [
                        change.device,
                        f"{change.from_revision} -> {change.to_revision}",
                        change.captured_at,
                        change.summary.lines_added,
                        change.summary.lines_removed,
                        _interface_change_text(change.summary.interfaces),
                    ]
                    for change in report.changes
                ],
            )
        )
    else:
        lines.append("No device has more than one revision yet.")
    lines.extend(("", "## Failing checks", ""))
    failing_rows = [
        [audit.device.name, finding.severity, finding.rule_id, finding.title]
        for audit in report.audit.device_audits
        for finding in audit.failures
    ]
    if failing_rows:
        lines.append(_markdown_table(["Device", "Severity", "Rule", "Title"], failing_rows))
    else:
        lines.append("No failing checks.")
    lines.append("")
    return "\n".join(lines)


def render_estate_html(report: EstateReport) -> str:
    """Render the estate report as a standalone HTML document."""
    parts = [
        "<h1>netvault estate report</h1>",
        '<ul class="meta">',
    ]
    parts.extend(f"<li>{_esc(label)}: {_esc(value)}</li>" for label, value in _estate_summary_pairs(report))
    parts.extend(("<h2>Device inventory</h2>",))
    inventory_rows = [
        [
            summary.name,
            _vendor_label(summary.vendor),
            summary.site or "-",
            summary.revisions,
            summary.latest_revision,
            summary.latest_captured_at or "-",
            _estate_score(report, summary.name),
        ]
        for summary in report.devices
    ]
    if inventory_rows:
        parts.append(
            _html_table(
                ["Device", "Vendor", "Site", "Revisions", "Latest revision", "Last snapshot", "Compliance score"],
                inventory_rows,
            )
        )
    else:
        parts.append("<p>No devices in the vault yet.</p>")

    parts.append("<h2>Recent changes</h2>")
    if report.changes:
        parts.append(
            _html_table(
                ["Device", "Change", "Captured", "Lines added", "Lines removed", "Interfaces"],
                [
                    [
                        change.device,
                        f"{change.from_revision} -> {change.to_revision}",
                        change.captured_at,
                        change.summary.lines_added,
                        change.summary.lines_removed,
                        _interface_change_text(change.summary.interfaces),
                    ]
                    for change in report.changes
                ],
            )
        )
    else:
        parts.append("<p>No device has more than one revision yet.</p>")

    parts.append("<h2>Failing checks</h2>")
    failing_rows: list[list[object]] = []
    failing_classes: list[list[str]] = []
    for audit in report.audit.device_audits:
        for finding in audit.failures:
            failing_rows.append([audit.device.name, finding.severity, finding.rule_id, finding.title])
            failing_classes.append(["", _severity_css(finding.severity), "", ""])
    if failing_rows:
        parts.append(
            _html_table(
                ["Device", "Severity", "Rule", "Title"],
                failing_rows,
                failing_classes,
            )
        )
    else:
        parts.append('<p class="all-clear">No failing checks.</p>')
    return _html_document("netvault estate report", "\n".join(parts))

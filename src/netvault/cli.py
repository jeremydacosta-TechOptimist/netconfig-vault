"""Command line interface for netvault.

Sub-commands cover the whole lifecycle: create a vault, collect snapshots,
inspect history, diff revisions, audit compliance and generate estate reports.
Exit codes are documented in ``netvault --help``.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .baselines import builtin_rules
from .collector import CollectionIssue, collect_directory
from .compliance import audit_vault
from .diffing import build_diff
from .models import VENDOR_LABELS
from .normalize import content_digest, normalize_config
from .reports import (
    build_estate_report,
    render_audit_html,
    render_audit_markdown,
    render_audit_text,
    render_diff_html,
    render_diff_markdown,
    render_diff_text,
    render_estate_html,
    render_estate_markdown,
    render_estate_text,
    render_table,
)
from .rules import Rule, RuleError, load_rule_file, merge_rules
from .store import SCHEMA_VERSION, Vault, VaultError, utc_now_iso

PROG = "netvault"
DEFAULT_VAULT = "vault"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

_REPORT_FORMATS = ("text", "md", "html")
_FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "any", "none")


def _revision_argument(value: str) -> int | str:
    """argparse type for a revision number or the ``latest`` keyword."""
    if value.lower() == "latest":
        return "latest"
    try:
        revision = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid revision {value!r}; expected an integer or 'latest'"
        ) from exc
    if revision < 1:
        raise argparse.ArgumentTypeError("revision numbers start at 1")
    return revision


def _positive_int(value: str) -> int:
    """argparse type for a positive integer."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def _non_negative_int(value: str) -> int:
    """argparse type for a non-negative integer."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must be at least 0")
    return number


def _default_vault() -> str:
    """Return the default vault path, honoring ``NETVAULT_VAULT``."""
    return os.environ.get("NETVAULT_VAULT", DEFAULT_VAULT)


def _vendor_label(vendor: str) -> str:
    """Return the display label for a vendor identifier."""
    return VENDOR_LABELS.get(vendor, vendor)


def _print_issues(issues: Sequence[CollectionIssue]) -> None:
    """Report collection problems on stderr."""
    for issue in issues:
        print(f"error: {issue.source}: {issue.message}", file=sys.stderr)


def _emit(text: str, out: str | None, description: str) -> None:
    """Print a rendered report or write it to *out* with LF line endings."""
    if out is None:
        print(text)
        return
    path = Path(out)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")
    print(f"Wrote {description} to {out}")


def _load_rules(rule_files: Sequence[str]) -> tuple[Rule, ...]:
    """Merge the built-in baselines with every supplied JSON rule file."""
    rules = list(builtin_rules())
    for rule_file in rule_files:
        rules = list(merge_rules(rules, load_rule_file(rule_file)))
    return tuple(rules)


def _cmd_init(args: argparse.Namespace) -> int:
    """Create a vault directory and print its state."""
    vault = Vault.initialize(args.vault)
    stats = vault.stats()
    print(f"Vault ready at: {vault.display_path}")
    print(f"Schema version: {SCHEMA_VERSION}")
    print(f"Devices in vault: {stats.devices}")
    return EXIT_SUCCESS


def _cmd_snapshot(args: argparse.Namespace) -> int:
    """Collect configuration exports into the vault."""
    result = collect_directory(args.directory)
    if not result.configs and not result.issues:
        print(
            f"error: no configuration files found under {args.directory}",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    if args.dry_run:
        print(f"Dry run - {len(result.configs)} configuration(s) collected")
        for config in result.configs:
            normalized = normalize_config(config.content)
            digest = content_digest(config.content)
            print(
                f"  {config.info.name} ({_vendor_label(config.info.vendor)}): "
                f"digest {digest[:12]}, {len(normalized.splitlines())} lines, "
                f"source {config.source}"
            )
        _print_issues(result.issues)
        return EXIT_FAILURE if result.issues else EXIT_SUCCESS

    vault = Vault.open(args.vault)
    print(f"Collecting from {args.directory}")
    created = 0
    unchanged = 0
    for config in result.configs:
        outcome = vault.snapshot(
            config.info,
            config.content,
            note=args.note,
            source_name=config.source,
        )
        record = outcome.record
        if outcome.created:
            created += 1
            state = f"revision {record.revision} created"
        else:
            unchanged += 1
            state = f"revision {record.revision} unchanged (identical to latest)"
        print(
            f"  {record.device} ({_vendor_label(record.vendor)}): {state}, "
            f"digest {record.digest[:12]}, {record.line_count} lines"
        )
    _print_issues(result.issues)
    print(
        f"Summary: {created} new revision(s), {unchanged} unchanged, "
        f"{len(result.issues)} error(s)"
    )
    return EXIT_FAILURE if result.issues else EXIT_SUCCESS


def _cmd_devices(args: argparse.Namespace) -> int:
    """List the devices stored in the vault."""
    vault = Vault.open(args.vault)
    summaries = vault.list_devices()
    if not summaries:
        print("No devices in the vault. Collect configurations with: netvault snapshot <dir>")
        return EXIT_SUCCESS
    rows = [
        [
            summary.name,
            _vendor_label(summary.vendor),
            summary.site or "-",
            str(summary.revisions),
            str(summary.latest_revision),
            summary.latest_captured_at or "-",
        ]
        for summary in summaries
    ]
    print(
        render_table(
            ["NAME", "VENDOR", "SITE", "REVISIONS", "LATEST", "LAST SNAPSHOT"],
            rows,
        )
    )
    return EXIT_SUCCESS


def _cmd_history(args: argparse.Namespace) -> int:
    """Show the revision history of one device."""
    vault = Vault.open(args.vault)
    records = vault.history(args.device)
    summary = next(
        (item for item in vault.list_devices() if item.name.lower() == args.device.lower()),
        None,
    )
    header = f"History for {summary.name if summary else args.device}"
    if summary is not None:
        header += f" ({_vendor_label(summary.vendor)}, site: {summary.site or 'n/a'})"
    print(header)
    if args.limit is not None:
        records = records[-args.limit :]
    rows = [
        [
            str(record.revision),
            record.captured_at,
            record.digest[:12],
            str(record.line_count),
            str(record.size_bytes),
            record.note or "-",
        ]
        for record in records
    ]
    print(
        render_table(
            ["REV", "CAPTURED (UTC)", "DIGEST", "LINES", "BYTES", "NOTE"],
            rows,
        )
    )
    return EXIT_SUCCESS


def _cmd_diff(args: argparse.Namespace) -> int:
    """Diff two revisions of one device."""
    vault = Vault.open(args.vault)
    latest = vault.latest_snapshot(args.device)
    from_revision = latest.revision if args.rev1 == "latest" else int(args.rev1)
    to_revision = latest.revision if args.rev2 == "latest" else int(args.rev2)
    from_record, from_text = vault.read_revision(args.device, from_revision)
    to_record, to_text = vault.read_revision(args.device, to_revision)
    result = build_diff(
        device=from_record.device,
        old_text=from_text,
        new_text=to_text,
        from_revision=from_record.revision,
        to_revision=to_record.revision,
        from_digest=from_record.digest,
        to_digest=to_record.digest,
        from_captured_at=from_record.captured_at,
        to_captured_at=to_record.captured_at,
        context=args.context,
    )
    renderers = {
        "text": render_diff_text,
        "md": render_diff_markdown,
        "html": render_diff_html,
    }
    if args.summary_only and args.format == "text":
        text = result.summary.render_text()
    elif args.format == "text":
        text = renderers["text"](result)
    else:
        text = renderers[args.format](result, include_diff=not args.summary_only)
    _emit(text, args.out, f"change report ({args.format})")
    return EXIT_SUCCESS


def _cmd_audit(args: argparse.Namespace) -> int:
    """Run compliance checks against the latest revision of each device."""
    vault = Vault.open(args.vault)
    rules = _load_rules(args.rules)
    report = audit_vault(
        vault,
        rules=rules,
        devices=args.devices or None,
        generated_at=utc_now_iso(),
    )
    renderers = {
        "text": render_audit_text,
        "md": render_audit_markdown,
        "html": render_audit_html,
    }
    _emit(renderers[args.format](report), args.out, f"compliance report ({args.format})")
    if args.out is not None:
        print(
            f"overall: {report.status} - {report.total_failed} failure(s), "
            f"{report.critical_failures} critical"
        )
    return EXIT_FAILURE if report.failures_at_or_above(args.fail_on) else EXIT_SUCCESS


def _cmd_report(args: argparse.Namespace) -> int:
    """Generate a whole-vault estate report."""
    vault = Vault.open(args.vault)
    rules = _load_rules(args.rules)
    report = build_estate_report(vault, rules=rules, generated_at=utc_now_iso())
    renderers = {
        "text": render_estate_text,
        "md": render_estate_markdown,
        "html": render_estate_html,
    }
    _emit(renderers[args.format](report), args.out, f"estate report ({args.format})")
    return EXIT_SUCCESS


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Content-addressed network configuration vault: collect, version, "
            "diff and audit device configurations offline."
        ),
        epilog=(
            "exit codes:\n"
            "  0  success\n"
            "  1  runtime failure, unknown device or revision, snapshot errors, or a\n"
            "     compliance finding at or above --fail-on (audit)\n"
            "  2  invalid command line usage\n"
            "\n"
            "examples:\n"
            "  netvault init\n"
            "  netvault snapshot examples/lab-configs/baseline\n"
            "  netvault history core-sw-01\n"
            "  netvault diff core-sw-01 1 2\n"
            "  netvault audit --rules examples/rules/lab-baseline.json\n"
            "  netvault report --format html --out estate.html"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--vault",
        default=_default_vault(),
        metavar="PATH",
        help="vault directory (default: %(default)s, env: NETVAULT_VAULT)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROG} {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=True)

    init_parser = subparsers.add_parser(
        "init",
        help="create a vault directory and SQLite index",
        description="Create (or verify) a vault directory. Safe to run repeatedly.",
    )
    init_parser.set_defaults(handler=_cmd_init)

    snapshot_parser = subparsers.add_parser(
        "snapshot",
        help="collect configuration exports from a directory",
        description=(
            "Scan a directory tree for configuration exports, derive device "
            "metadata and store one immutable revision per changed device."
        ),
    )
    snapshot_parser.add_argument("directory", metavar="DIR", help="directory to scan")
    snapshot_parser.add_argument(
        "--note",
        default="",
        metavar="TEXT",
        help="note stored with newly created revisions",
    )
    snapshot_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be stored without writing to the vault",
    )
    snapshot_parser.set_defaults(handler=_cmd_snapshot)

    devices_parser = subparsers.add_parser(
        "devices",
        help="list devices stored in the vault",
        description="Print the device inventory with revision counters.",
    )
    devices_parser.set_defaults(handler=_cmd_devices)

    history_parser = subparsers.add_parser(
        "history",
        help="show the revision history of a device",
        description="Print every stored revision of one device in chronological order.",
    )
    history_parser.add_argument("device", metavar="DEVICE", help="device name")
    history_parser.add_argument(
        "--limit",
        type=_positive_int,
        default=None,
        metavar="N",
        help="show only the newest N revisions",
    )
    history_parser.set_defaults(handler=_cmd_history)

    diff_parser = subparsers.add_parser(
        "diff",
        help="diff two revisions of a device",
        description=(
            "Show a unified diff plus a semantic change summary (interfaces, ACL "
            "and route lines, configuration size)."
        ),
    )
    diff_parser.add_argument("device", metavar="DEVICE", help="device name")
    diff_parser.add_argument(
        "rev1",
        metavar="REV1",
        type=_revision_argument,
        help="first revision (number or 'latest')",
    )
    diff_parser.add_argument(
        "rev2",
        metavar="REV2",
        type=_revision_argument,
        help="second revision (number or 'latest')",
    )
    diff_parser.add_argument(
        "--context",
        type=_non_negative_int,
        default=3,
        metavar="N",
        help="unified diff context lines (default: %(default)s)",
    )
    diff_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="print only the semantic change summary, without the unified diff",
    )
    diff_parser.add_argument(
        "--format",
        choices=_REPORT_FORMATS,
        default="text",
        help="output format (default: %(default)s)",
    )
    diff_parser.add_argument("--out", metavar="PATH", help="write the report to a file")
    diff_parser.set_defaults(handler=_cmd_diff)

    audit_parser = subparsers.add_parser(
        "audit",
        help="check compliance of the latest revisions",
        description=(
            "Evaluate built-in Cisco IOS and Aruba/HP baselines plus optional JSON "
            "rule files against the latest revision of each device."
        ),
    )
    audit_parser.add_argument(
        "devices",
        nargs="*",
        metavar="DEVICE",
        help="devices to audit (default: all devices in the vault)",
    )
    audit_parser.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="FILE",
        help="JSON rule file to merge with the built-in baselines (repeatable)",
    )
    audit_parser.add_argument(
        "--format",
        choices=_REPORT_FORMATS,
        default="text",
        help="output format (default: %(default)s)",
    )
    audit_parser.add_argument("--out", metavar="PATH", help="write the report to a file")
    audit_parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="critical",
        help=(
            "exit 1 when a finding at or above this severity exists "
            "(default: %(default)s)"
        ),
    )
    audit_parser.set_defaults(handler=_cmd_audit)

    report_parser = subparsers.add_parser(
        "report",
        help="generate a whole-vault estate report",
        description=(
            "Combine the device inventory, recent changes and latest compliance "
            "state into one report."
        ),
    )
    report_parser.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="FILE",
        help="JSON rule file to merge with the built-in baselines (repeatable)",
    )
    report_parser.add_argument(
        "--format",
        choices=_REPORT_FORMATS,
        default="text",
        help="output format (default: %(default)s)",
    )
    report_parser.add_argument("--out", metavar="PATH", help="write the report to a file")
    report_parser.set_defaults(handler=_cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (VaultError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except sqlite3.Error as exc:
        print(f"error: database error: {exc}", file=sys.stderr)
        return EXIT_FAILURE

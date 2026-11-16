"""Tests for text, Markdown and standalone HTML report rendering."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from netvault.compliance import AuditReport, DeviceAudit, Finding
from netvault.diffing import build_diff
from netvault.models import STATUS_FAIL, STATUS_PASS, DeviceInfo
from netvault.reports import (
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
from netvault.store import Vault

BASE_CONFIG = "hostname core-sw-01\ninterface GigabitEthernet0/1\n description uplink\n!\n"
CHANGED_CONFIG = (
    BASE_CONFIG.replace(" description uplink", " description uplink-to-edge")
    + "ip route 0.0.0.0 0.0.0.0 198.51.100.1\n"
)


def make_finding(
    rule_id: str,
    title: str,
    severity: str,
    status: str,
    details: tuple[str, ...] = (),
    remediation: str = "",
) -> Finding:
    """Build a finding fixture."""
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        status=status,
        details=details,
        remediation=remediation,
    )


def make_audit(name: str = "edge-rtr-01") -> DeviceAudit:
    """Build a device audit fixture with two failures and one pass."""
    findings = (
        make_finding(
            "CISCO-TELNET-001",
            "VTY transport restricted to SSH (no Telnet)",
            "critical",
            STATUS_FAIL,
            ("forbidden pattern matched line 3: transport input all",),
            "Set 'transport input ssh' on every VTY line.",
        ),
        make_finding(
            "CISCO-HTTP-001",
            "Cleartext HTTP management server disabled",
            "high",
            STATUS_FAIL,
            ("forbidden pattern matched line 5: ip http server",),
            "Remove 'ip http server'.",
        ),
        make_finding(
            "CISCO-NTP-001",
            "NTP servers configured",
            "medium",
            STATUS_PASS,
            (),
            "Configure at least one 'ntp server <address>' entry.",
        ),
    )
    return DeviceAudit(
        device=DeviceInfo(name=name, vendor="cisco-ios", site="porto-lab"),
        revision=2,
        digest="a" * 64,
        captured_at="2026-01-02T00:00:00Z",
        findings=findings,
    )


def make_report(device_audits: tuple[DeviceAudit, ...] | None = None) -> AuditReport:
    """Build a compliance audit report fixture."""
    return AuditReport(
        vault_path="vault",
        generated_at="2026-01-03T00:00:00Z",
        device_audits=(make_audit(),) if device_audits is None else device_audits,
        rule_definitions=21,
        custom_rule_count=0,
    )


def make_diff_result():
    """Build a diff result fixture from the sample configurations."""
    return build_diff(
        device="core-sw-01",
        old_text=BASE_CONFIG,
        new_text=CHANGED_CONFIG,
        from_revision=1,
        to_revision=2,
        from_digest="a" * 64,
        to_digest="b" * 64,
        from_captured_at="2026-01-01T00:00:00Z",
        to_captured_at="2026-01-02T00:00:00Z",
    )


class RenderTableTest(unittest.TestCase):
    def test_table_is_aligned_with_header_separator(self) -> None:
        rendered = render_table(["NAME", "COUNT"], [["core-sw-01", "2"], ["edge", "10"]])
        lines = rendered.splitlines()
        self.assertEqual(lines[0].split(), ["NAME", "COUNT"])
        self.assertTrue(set(lines[1]) == {"-", " "})
        self.assertIn("core-sw-01", lines[2])
        self.assertIn("10", lines[3])

    def test_row_width_mismatch_raises(self) -> None:
        with self.assertRaises(ValueError):
            render_table(["A", "B"], [["only-one-cell"]])


class AuditTextReportTest(unittest.TestCase):
    def test_text_report_contains_headline_and_failures(self) -> None:
        text = render_audit_text(make_report())
        self.assertIn("Compliance audit - 1 device(s), 21 rule definition(s)", text)
        self.assertIn("overall: FAIL - 1 critical, 1 high failure(s)", text)
        self.assertIn("edge-rtr-01 (Cisco IOS, rev 2)", text)
        self.assertIn("FAIL critical CISCO-TELNET-001", text)
        self.assertIn("FAIL high     CISCO-HTTP-001", text)
        self.assertIn("Summary: 1 pass, 2 fail, 0 skip", text)

    def test_empty_report_is_explicit(self) -> None:
        text = render_audit_text(
            AuditReport("vault", "2026-01-03T00:00:00Z", (), rule_definitions=21, custom_rule_count=0)
        )
        self.assertIn("PASS", text)
        self.assertIn("No devices in the vault were audited.", text)


class AuditMarkdownReportTest(unittest.TestCase):
    def test_markdown_report_contains_expected_sections(self) -> None:
        report = make_report()
        markdown = render_audit_markdown(report)
        self.assertTrue(markdown.startswith("# Compliance audit"))
        self.assertIn("- Generated: 2026-01-03T00:00:00Z", markdown)
        self.assertIn("- Vault: vault", markdown)
        self.assertIn("## Summary", markdown)
        self.assertIn("| Device | Vendor | Site | Revision | Score |", markdown)
        self.assertIn("## Findings", markdown)
        self.assertIn("### edge-rtr-01 (Cisco IOS, revision 2)", markdown)
        self.assertIn("CISCO-TELNET-001", markdown)
        self.assertIn("## Remediation", markdown)
        self.assertIn("Set 'transport input ssh' on every VTY line.", markdown)

    def test_markdown_escapes_pipes_in_table_cells(self) -> None:
        audit = DeviceAudit(
            device=DeviceInfo(name="weird|device", vendor="cisco-ios"),
            revision=1,
            digest="a" * 64,
            captured_at="2026-01-01T00:00:00Z",
            findings=(
                make_finding("CUSTOM-001", "title | with pipe", "low", STATUS_PASS),
            ),
        )
        markdown = render_audit_markdown(make_report((audit,)))
        self.assertIn("weird\\|device", markdown)
        self.assertIn("title \\| with pipe", markdown)

    def test_all_passing_report_has_no_remediation_entries(self) -> None:
        audit = DeviceAudit(
            device=DeviceInfo(name="core-sw-01", vendor="cisco-ios"),
            revision=1,
            digest="a" * 64,
            captured_at="2026-01-01T00:00:00Z",
            findings=(make_finding("CISCO-SSH-001", "SSHv2", "high", STATUS_PASS),),
        )
        markdown = render_audit_markdown(make_report((audit,)))
        self.assertIn("No failing checks.", markdown)


class AuditHtmlReportTest(unittest.TestCase):
    def test_html_report_is_standalone_without_external_assets(self) -> None:
        page = render_audit_html(make_report())
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertIn('<html lang="en">', page)
        self.assertIn("<style>", page)
        self.assertIn("</html>", page)
        lowered = page.lower()
        self.assertNotIn("<script", lowered)
        self.assertNotIn("<link", lowered)
        self.assertNotIn("http://", lowered)
        self.assertNotIn("https://", lowered)
        self.assertNotIn("url(", lowered)
        self.assertIn("Generated by netvault", page)

    def test_html_report_contains_status_and_severity_classes(self) -> None:
        page = render_audit_html(make_report())
        self.assertIn('class="status-fail"', page)
        self.assertIn('class="severity-critical"', page)
        self.assertIn('class="severity-high"', page)
        self.assertIn('class="severity-medium"', page)

    def test_html_report_escapes_dynamic_content(self) -> None:
        audit = DeviceAudit(
            device=DeviceInfo(name="<script>alert(1)</script>", vendor="cisco-ios"),
            revision=1,
            digest="a" * 64,
            captured_at="2026-01-01T00:00:00Z",
            findings=(
                make_finding(
                    "CUSTOM-002",
                    "unsafe <b>title</b> & more",
                    "low",
                    STATUS_FAIL,
                    ("detail with <tag>",),
                ),
            ),
        )
        page = render_audit_html(make_report((audit,)))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("unsafe &lt;b&gt;title&lt;/b&gt; &amp; more", page)

    def test_passing_report_has_all_clear_message(self) -> None:
        audit = DeviceAudit(
            device=DeviceInfo(name="core-sw-01", vendor="cisco-ios"),
            revision=1,
            digest="a" * 64,
            captured_at="2026-01-01T00:00:00Z",
            findings=(make_finding("CISCO-SSH-001", "SSHv2", "high", STATUS_PASS),),
        )
        page = render_audit_html(make_report((audit,)))
        self.assertIn("No failing checks.", page)
        self.assertIn("status-pass", page)


class ChangeReportTest(unittest.TestCase):
    def test_text_change_report_includes_summary_and_unified_diff(self) -> None:
        text = render_diff_text(make_diff_result())
        self.assertIn("Change summary - core-sw-01 (revision 1 -> 2)", text)
        self.assertIn("lines: +2 / -1 (net +1)", text)
        self.assertIn("@@", text)

    def test_markdown_change_report_contains_metadata_and_diff(self) -> None:
        markdown = render_diff_markdown(make_diff_result())
        self.assertTrue(markdown.startswith("# Change report - core-sw-01"))
        self.assertIn("- From revision: 1 (2026-01-01T00:00:00Z)", markdown)
        self.assertIn("- To revision: 2 (2026-01-02T00:00:00Z)", markdown)
        self.assertIn("- Interfaces modified: GigabitEthernet0/1", markdown)
        self.assertIn("## Unified diff", markdown)
        self.assertIn("```diff", markdown)
        self.assertIn("description uplink-to-edge", markdown)

    def test_unchanged_revisions_render_a_no_change_report(self) -> None:
        result = build_diff(
            device="core-sw-01",
            old_text=BASE_CONFIG,
            new_text=BASE_CONFIG,
            from_revision=1,
            to_revision=3,
        )
        markdown = render_diff_markdown(result)
        self.assertIn("No changes between the two revisions.", markdown)
        self.assertNotIn("```diff", markdown)
        self.assertIn("No changes between revision 1 and revision 3.", render_diff_text(result))

    def test_html_change_report_has_colour_coded_diff(self) -> None:
        page = render_diff_html(make_diff_result())
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertIn('<pre class="diff">', page)
        self.assertIn("diff-add", page)
        self.assertIn("diff-del", page)
        self.assertIn("diff-file", page)
        lowered = page.lower()
        self.assertNotIn("<script", lowered)
        self.assertNotIn("http://", lowered)
        self.assertNotIn("https://", lowered)

    def test_markdown_change_report_can_omit_the_unified_diff(self) -> None:
        markdown = render_diff_markdown(make_diff_result(), include_diff=False)
        self.assertIn("- Lines added: 2", markdown)
        self.assertNotIn("## Unified diff", markdown)

    def test_html_change_report_can_omit_the_unified_diff(self) -> None:
        page = render_diff_html(make_diff_result(), include_diff=False)
        self.assertNotIn('<pre class="diff">', page)
        self.assertIn("Lines added", page)


class EstateReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.vault = Vault.initialize(Path(self._temporary.name) / "vault")
        self.vault.snapshot(
            DeviceInfo(name="core-sw-01", vendor="cisco-ios", site="porto-lab"),
            "hostname core-sw-01\nip http server\n",
            captured_at="2026-01-01T00:00:00Z",
            note="initial",
        )
        self.vault.snapshot(
            DeviceInfo(name="core-sw-01", vendor="cisco-ios", site="porto-lab"),
            "hostname core-sw-01\nip http server\nip ssh version 1\n",
            captured_at="2026-01-02T00:00:00Z",
        )

    def build_report(self):
        """Build the estate report used by rendering assertions."""
        return build_estate_report(self.vault, generated_at="2026-01-03T00:00:00Z")

    def test_estate_report_collects_inventory_changes_and_compliance(self) -> None:
        report = self.build_report()
        self.assertEqual(report.generated_at, "2026-01-03T00:00:00Z")
        self.assertEqual(report.stats.devices, 1)
        self.assertEqual(report.stats.snapshots, 2)
        self.assertEqual(len(report.changes), 1)
        change = report.changes[0]
        self.assertEqual((change.from_revision, change.to_revision), (1, 2))
        self.assertEqual(change.summary.lines_added, 1)
        self.assertEqual(len(report.audit.device_audits), 1)

    def test_estate_text_report_contains_sections(self) -> None:
        text = render_estate_text(self.build_report())
        self.assertIn("netvault estate report", text)
        self.assertIn("Estate summary", text)
        self.assertIn("Device inventory", text)
        self.assertIn("Recent changes", text)
        self.assertIn("core-sw-01", text)
        self.assertIn("1 -> 2", text)
        self.assertIn("compliance", text)

    def test_estate_markdown_report_contains_sections(self) -> None:
        markdown = render_estate_markdown(self.build_report())
        self.assertTrue(markdown.startswith("# netvault estate report"))
        self.assertIn("- Generated: 2026-01-03T00:00:00Z", markdown)
        self.assertIn("## Device inventory", markdown)
        self.assertIn("## Recent changes", markdown)
        self.assertIn("## Failing checks", markdown)
        self.assertIn("CISCO-HTTP-001", markdown)

    def test_estate_html_report_is_standalone_without_external_assets(self) -> None:
        page = render_estate_html(self.build_report())
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertIn("<h1>netvault estate report</h1>", page)
        lowered = page.lower()
        self.assertNotIn("<script", lowered)
        self.assertNotIn("http://", lowered)
        self.assertNotIn("https://", lowered)
        self.assertNotIn("url(", lowered)

    def test_estate_report_on_empty_vault(self) -> None:
        empty = Vault.initialize(Path(self._temporary.name) / "empty-vault")
        report = build_estate_report(empty, generated_at="2026-01-03T00:00:00Z")
        self.assertEqual(report.changes, ())
        text = render_estate_text(report)
        self.assertIn("No device has more than one revision yet.", text)
        markdown = render_estate_markdown(report)
        self.assertIn("No failing checks.", markdown)


if __name__ == "__main__":
    unittest.main()

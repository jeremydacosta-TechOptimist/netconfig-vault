"""Tests for compliance rule validation, evaluation and audit aggregation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from netvault.baselines import builtin_rules, rules_for_vendor
from netvault.compliance import (
    AuditReport,
    DeviceAudit,
    Finding,
    audit_vault,
    evaluate_config,
)
from netvault.models import (
    SEVERITIES,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    DeviceInfo,
)
from netvault.rules import Rule, RuleError, load_rule_file, merge_rules, rule_from_mapping
from netvault.store import UnknownDeviceError, Vault

REPO_ROOT = Path(__file__).resolve().parents[1]

# Minimal fixtures that pass and fail each built-in rule on its own. Keeping
# them minimal makes a failure point directly at the rule under test.
CISCO_FIXTURES: dict[str, tuple[str, str]] = {
    "CISCO-SSH-001": ("ip ssh version 2\n", "ip ssh version 1\n"),
    "CISCO-TELNET-001": (
        "line vty 0 4\n transport input ssh\n",
        "line vty 0 4\n transport input all\n",
    ),
    "CISCO-PWD-001": ("hostname core-sw-01\n", "enable password labonly\n"),
    "CISCO-NTP-001": ("ntp server 203.0.113.10\n", "hostname core-sw-01\n"),
    "CISCO-LOG-001": ("logging host 203.0.113.20\n", "hostname core-sw-01\n"),
    "CISCO-BANNER-001": (
        "banner motd ^C Authorised access only ^C\n",
        "hostname core-sw-01\n",
    ),
    "CISCO-AUTH-001": ("aaa new-model\n", "hostname core-sw-01\n"),
    "CISCO-AUTH-002": (
        "aaa authentication login default local\n",
        "hostname core-sw-01\n",
    ),
    "CISCO-HTTP-001": ("ip http secure-server\n", "ip http server\n"),
    "CISCO-SNMP-001": (
        "snmp-server community NETLAB-RO RO\n",
        "snmp-server community public RO\n",
    ),
    "CISCO-VLAN-001": ("switchport access vlan 20\n", "switchport access vlan 1\n"),
}

ARUBA_FIXTURES: dict[str, tuple[str, str]] = {
    "ARUBA-SSH-001": ("ip ssh\n", "no ip ssh\n"),
    "ARUBA-TELNET-001": ("no telnet-server\n", 'hostname "sw1"\n'),
    "ARUBA-PWD-001": ('hostname "sw1"\n', "password manager plaintext labonly\n"),
    "ARUBA-NTP-001": ("ntp server priority 1 203.0.113.10\n", 'hostname "sw1"\n'),
    "ARUBA-LOG-001": ("logging 203.0.113.20\n", "logging facility local5\n"),
    "ARUBA-BANNER-001": ('banner motd "Authorised access only"\n', 'hostname "sw1"\n'),
    "ARUBA-AUTH-001": (
        "aaa authentication ssh login radius local\n",
        'hostname "sw1"\n',
    ),
    "ARUBA-WEB-001": ("web-management ssl\n", "web-management plaintext\n"),
    "ARUBA-SNMP-001": (
        'snmp-server community "NETLAB-RO" restricted\n',
        'snmp-server community "public" restricted\n',
    ),
    "ARUBA-STP-001": ("spanning-tree\n", 'hostname "sw1"\n'),
}

COMPLIANT_CISCO = (
    "hostname test-core\n"
    "aaa new-model\n"
    "aaa authentication login default local\n"
    "ip ssh version 2\n"
    "line vty 0 4\n"
    " transport input ssh\n"
    "ntp server 203.0.113.10\n"
    "logging host 203.0.113.20\n"
    "banner motd ^C Authorised access only ^C\n"
)

FAILING_CISCO = (
    "hostname edge-rtr-01\n"
    "line vty 0 4\n"
    " transport input all\n"
    "ip http server\n"
    "snmp-server community public RO\n"
)


def make_finding(
    rule_id: str,
    severity: str,
    status: str,
    details: tuple[str, ...] = (),
) -> Finding:
    """Build a finding for report aggregation tests."""
    return Finding(
        rule_id=rule_id,
        title=f"title for {rule_id}",
        severity=severity,
        status=status,
        details=details,
        remediation="do something",
    )


def make_device_audit(
    findings: tuple[Finding, ...], name: str = "core-sw-01"
) -> DeviceAudit:
    """Build a device audit for report aggregation tests."""
    return DeviceAudit(
        device=DeviceInfo(name=name, vendor="cisco-ios", site="porto-lab"),
        revision=1,
        digest="a" * 64,
        captured_at="2026-01-01T00:00:00Z",
        findings=findings,
    )


def make_report(
    device_audits: tuple[DeviceAudit, ...], rule_definitions: int = 3
) -> AuditReport:
    """Build an audit report for aggregation tests."""
    return AuditReport(
        vault_path="vault",
        generated_at="2026-01-02T00:00:00Z",
        device_audits=device_audits,
        rule_definitions=rule_definitions,
        custom_rule_count=0,
    )


class BuiltinBaselineTest(unittest.TestCase):
    def test_baseline_catalogue_is_complete_and_consistent(self) -> None:
        rules = builtin_rules()
        self.assertEqual(len(rules), 21)
        self.assertEqual(len({rule.id for rule in rules}), 21)
        self.assertEqual(len(rules_for_vendor("cisco-ios")), 11)
        self.assertEqual(len(rules_for_vendor("aruba")), 10)
        for rule in rules:
            with self.subTest(rule=rule.id):
                self.assertIn(rule.severity, SEVERITIES)
                self.assertEqual(len(rule.vendors), 1)
                self.assertTrue(rule.remediation)
                self.assertEqual(rule.source, "built-in")

    def test_every_builtin_rule_has_a_pass_and_fail_fixture(self) -> None:
        fixture_ids = set(CISCO_FIXTURES) | set(ARUBA_FIXTURES)
        rule_ids = {rule.id for rule in builtin_rules()}
        self.assertEqual(fixture_ids, rule_ids)

    def test_builtin_rules_pass_their_positive_fixture(self) -> None:
        for rule in builtin_rules():
            fixtures = CISCO_FIXTURES if rule.vendors[0] == "cisco-ios" else ARUBA_FIXTURES
            pass_config = fixtures[rule.id][0]
            with self.subTest(rule=rule.id):
                findings = evaluate_config(pass_config, (rule,), vendor=rule.vendors[0])
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].status, STATUS_PASS)
                self.assertEqual(findings[0].details, ())

    def test_builtin_rules_fail_their_negative_fixture(self) -> None:
        for rule in builtin_rules():
            fixtures = CISCO_FIXTURES if rule.vendors[0] == "cisco-ios" else ARUBA_FIXTURES
            fail_config = fixtures[rule.id][1]
            with self.subTest(rule=rule.id):
                findings = evaluate_config(fail_config, (rule,), vendor=rule.vendors[0])
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].status, STATUS_FAIL)
                self.assertTrue(findings[0].details)
                self.assertEqual(findings[0].remediation, rule.remediation)

    def test_rules_are_scoped_to_their_vendor(self) -> None:
        cisco_rule = next(rule for rule in builtin_rules() if rule.vendors[0] == "cisco-ios")
        aruba_rule = next(rule for rule in builtin_rules() if rule.vendors[0] == "aruba")
        self.assertEqual(evaluate_config("hostname x\n", (cisco_rule,), vendor="aruba"), ())
        self.assertEqual(evaluate_config("hostname x\n", (aruba_rule,), vendor="cisco-ios"), ())

    def test_empty_configuration_skips_every_applicable_rule(self) -> None:
        findings = evaluate_config(" \n\n", rules_for_vendor("cisco-ios"), vendor="cisco-ios")
        self.assertEqual(len(findings), 11)
        self.assertTrue(all(finding.status == STATUS_SKIP for finding in findings))
        self.assertEqual(findings[0].details, ("empty configuration",))

    def test_aruba_web_rule_skips_when_web_management_is_disabled(self) -> None:
        rule = next(rule for rule in builtin_rules() if rule.id == "ARUBA-WEB-001")
        findings = evaluate_config("no web-management\n", (rule,), vendor="aruba")
        self.assertEqual(findings[0].status, STATUS_SKIP)
        self.assertIn("skip condition", findings[0].details[0])

    def test_compliant_cisco_configuration_passes_every_baseline_rule(self) -> None:
        findings = evaluate_config(
            COMPLIANT_CISCO, rules_for_vendor("cisco-ios"), vendor="cisco-ios"
        )
        self.assertEqual(
            [finding.rule_id for finding in findings if finding.status != STATUS_PASS],
            [],
        )


class RuleEvaluationDetailTest(unittest.TestCase):
    def test_must_match_requires_every_pattern(self) -> None:
        rule = Rule(
            id="CUSTOM-001",
            title="Need hostname and end marker",
            severity="high",
            vendors=("cisco-ios",),
            must_match=("^hostname r1$", "^end$"),
        )
        findings = evaluate_config("hostname r1\n", (rule,), vendor="cisco-ios")
        self.assertEqual(findings[0].status, STATUS_FAIL)
        self.assertEqual(findings[0].details, ("missing required pattern: ^end$",))

    def test_forbidden_matches_report_line_numbers_and_snippets(self) -> None:
        rule = Rule(
            id="CUSTOM-002",
            title="No telnet transport",
            severity="critical",
            vendors=("cisco-ios",),
            must_not_match=(r"^\s*transport input .*telnet",),
        )
        findings = evaluate_config(
            "hostname r1\nline vty 0 4\n transport input telnet\n",
            (rule,),
            vendor="cisco-ios",
        )
        self.assertEqual(findings[0].status, STATUS_FAIL)
        self.assertIn("line 3", findings[0].details[0])
        self.assertIn("transport input telnet", findings[0].details[0])

    def test_long_offending_lines_are_truncated_in_details(self) -> None:
        rule = Rule(
            id="CUSTOM-003",
            title="No long descriptions",
            severity="low",
            vendors=("cisco-ios",),
            must_not_match=(r"^description .{150,}$",),
        )
        long_line = "description " + "x" * 200
        findings = evaluate_config(long_line + "\n", (rule,), vendor="cisco-ios")
        detail = findings[0].details[0]
        self.assertLessEqual(len(detail), 150)
        self.assertIn("...", detail)

    def test_skip_if_marks_rule_as_skipped(self) -> None:
        rule = Rule(
            id="CUSTOM-004",
            title="AAA required unless legacy mode",
            severity="high",
            vendors=("cisco-ios",),
            must_match=(r"^aaa new-model$",),
            skip_if=(r"^no aaa legacy-mode$",),
        )
        findings = evaluate_config("no aaa legacy-mode\n", (rule,), vendor="cisco-ios")
        self.assertEqual(findings[0].status, STATUS_SKIP)


class RuleValidationTest(unittest.TestCase):
    BASE_RULE = {
        "id": "CUSTOM-100",
        "title": "Example check",
        "severity": "high",
        "must_match": ["^aaa new-model$"],
    }

    def test_valid_definition_is_accepted(self) -> None:
        rule = rule_from_mapping(self.BASE_RULE, source="custom.json")
        self.assertEqual(rule.id, "CUSTOM-100")
        self.assertEqual(rule.severity, "high")
        self.assertEqual(rule.vendors, ("cisco-ios", "aruba"))
        self.assertEqual(rule.source, "custom.json")

    def test_severity_is_normalized_to_lowercase(self) -> None:
        rule = rule_from_mapping({**self.BASE_RULE, "severity": "CRITICAL"}, source="custom.json")
        self.assertEqual(rule.severity, "critical")

    def test_single_string_matchers_and_vendors_are_accepted(self) -> None:
        rule = rule_from_mapping(
            {
                "id": "CUSTOM-101",
                "title": "Example check",
                "severity": "low",
                "vendors": "aruba",
                "must_not_match": "^telnet-server$",
            },
            source="custom.json",
        )
        self.assertEqual(rule.vendors, ("aruba",))
        self.assertEqual(rule.must_not_match, ("^telnet-server$",))

    def test_invalid_definitions_are_rejected(self) -> None:
        cases = {
            "missing id": {k: v for k, v in self.BASE_RULE.items() if k != "id"},
            "missing title": {k: v for k, v in self.BASE_RULE.items() if k != "title"},
            "invalid severity": {**self.BASE_RULE, "severity": "urgent"},
            "unknown field": {**self.BASE_RULE, "unexpected": True},
            "invalid regex": {**self.BASE_RULE, "must_match": ["["]},
            "no matchers": {"id": "CUSTOM-1", "title": "T", "severity": "high"},
            "empty pattern": {**self.BASE_RULE, "must_match": [""]},
            "unknown vendor": {**self.BASE_RULE, "vendors": ["juniper"]},
            "non-object": ["not", "an", "object"],
        }
        for name, raw in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(RuleError):
                    rule_from_mapping(raw, source="custom.json")  # type: ignore[arg-type]

    def test_direct_rule_construction_validates_fields(self) -> None:
        with self.assertRaises(RuleError):
            Rule(id="X-1", title="T", severity="urgent", must_match=("^a$",))
        with self.assertRaises(RuleError):
            Rule(id="X-1", title="T", severity="high", vendors=())


class RuleFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def write_rules(self, payload: object, name: str = "rules.json") -> Path:
        """Write a JSON rule file fixture."""
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_object_wrapper_format_is_loaded(self) -> None:
        path = self.write_rules(
            {
                "name": "custom",
                "description": "custom checks",
                "rules": [
                    {
                        "id": "ORG-001",
                        "title": "Require NTP",
                        "severity": "medium",
                        "vendors": ["cisco-ios"],
                        "must_match": ["^ntp server"],
                        "remediation": "add ntp",
                    }
                ],
            }
        )
        rules = load_rule_file(path)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].id, "ORG-001")
        self.assertEqual(rules[0].source, "rules.json")
        self.assertEqual(rules[0].vendors, ("cisco-ios",))

    def test_bare_list_format_is_loaded(self) -> None:
        path = self.write_rules(
            [
                {
                    "id": "ORG-002",
                    "title": "Require banner",
                    "severity": "low",
                    "must_match": ["^banner"],
                }
            ]
        )
        self.assertEqual([rule.id for rule in load_rule_file(path)], ["ORG-002"])

    def test_invalid_rule_files_are_rejected(self) -> None:
        invalid_payloads = {
            "empty rules": {"rules": []},
            "rules not a list": {"rules": {"id": "X-1"}},
            "unknown top level key": {"rules": [], "extra": 1},
            "duplicate ids": {
                "rules": [
                    {"id": "DUP-1", "title": "a", "severity": "low", "must_match": ["^a$"]},
                    {"id": "DUP-1", "title": "b", "severity": "low", "must_match": ["^b$"]},
                ]
            },
        }
        for name, payload in invalid_payloads.items():
            with self.subTest(case=name):
                path = self.write_rules(payload, name=f"{name}.json")
                with self.assertRaises(RuleError):
                    load_rule_file(path)
        bad_json = self.root / "broken.json"
        bad_json.write_text("{not json", encoding="utf-8")
        with self.assertRaises(RuleError):
            load_rule_file(bad_json)

    def test_missing_rule_file_raises_os_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_rule_file(self.root / "missing.json")

    def test_merge_rules_overrides_in_place_and_appends_new_rules(self) -> None:
        base = builtin_rules()
        override = Rule(
            id="CISCO-SSH-001",
            title="Custom SSH policy",
            severity="critical",
            vendors=("cisco-ios",),
            must_match=("^ip ssh version 2$",),
            source="custom.json",
        )
        appended = Rule(
            id="ORG-900",
            title="Organisation check",
            severity="low",
            vendors=("aruba",),
            must_match=("^spanning-tree$",),
            source="custom.json",
        )
        merged = merge_rules(base, (override, appended))
        self.assertEqual(merged[0].id, "CISCO-SSH-001")
        self.assertEqual(merged[0].source, "custom.json")
        self.assertEqual(merged[-1].id, "ORG-900")
        self.assertEqual(len(merged), len(base) + 1)

    def test_repository_example_rule_file_is_valid(self) -> None:
        path = REPO_ROOT / "examples" / "rules" / "lab-baseline.json"
        self.assertTrue(path.is_file(), f"missing rule file: {path}")
        rules = load_rule_file(path)
        self.assertEqual([rule.id for rule in rules], ["LAB-NTP-001", "LAB-LOG-001"])

    def test_example_rules_accept_baseline_and_flag_drift(self) -> None:
        rules = load_rule_file(REPO_ROOT / "examples" / "rules" / "lab-baseline.json")
        baseline = (REPO_ROOT / "examples" / "lab-configs" / "baseline" / "core-sw-01.cfg").read_text(
            encoding="utf-8"
        )
        drift = (REPO_ROOT / "examples" / "lab-configs" / "drift" / "edge-rtr-01.cfg").read_text(
            encoding="utf-8"
        )
        baseline_findings = evaluate_config(baseline, rules, vendor="cisco-ios")
        self.assertTrue(all(f.status == STATUS_PASS for f in baseline_findings))
        drift_findings = {f.rule_id: f for f in evaluate_config(drift, rules, vendor="cisco-ios")}
        self.assertEqual(drift_findings["LAB-LOG-001"].status, STATUS_FAIL)
        self.assertEqual(drift_findings["LAB-NTP-001"].status, STATUS_PASS)


class AuditAggregationTest(unittest.TestCase):
    def test_weighted_score_uses_severity_weights(self) -> None:
        audit = make_device_audit(
            (
                make_finding("R-1", "critical", STATUS_PASS),
                make_finding("R-2", "medium", STATUS_FAIL),
            )
        )
        self.assertEqual(audit.weighted_score, 76.9)
        self.assertEqual(audit.passed, 1)
        self.assertEqual(audit.failed, 1)
        self.assertEqual(audit.status, STATUS_FAIL)
        self.assertEqual(audit.critical_failures, 0)

    def test_score_is_zero_when_every_rule_is_skipped(self) -> None:
        audit = make_device_audit((make_finding("R-1", "critical", STATUS_SKIP),))
        self.assertEqual(audit.weighted_score, 0.0)

    def test_report_aggregates_totals_and_severity_breakdown(self) -> None:
        first = make_device_audit(
            (
                make_finding("R-1", "critical", STATUS_FAIL),
                make_finding("R-2", "high", STATUS_PASS),
            )
        )
        second = make_device_audit(
            (make_finding("R-3", "low", STATUS_FAIL),), name="edge-rtr-01"
        )
        report = make_report((first, second), rule_definitions=21)
        self.assertEqual((report.total_passed, report.total_failed, report.total_skipped), (1, 2, 0))
        self.assertEqual(report.critical_failures, 1)
        self.assertEqual(report.status, STATUS_FAIL)
        self.assertEqual(report.builtin_rule_count, 21)
        self.assertEqual(list(report.failures_by_severity), list(SEVERITIES))
        self.assertEqual(
            dict(report.failures_by_severity),
            {"critical": 1, "high": 0, "medium": 0, "low": 1},
        )

    def test_report_without_failures_passes(self) -> None:
        report = make_report(
            (make_device_audit((make_finding("R-1", "critical", STATUS_PASS),)),)
        )
        self.assertEqual(report.status, STATUS_PASS)
        self.assertEqual(report.overall_weighted_score, 100.0)

    def test_failures_at_or_above_threshold(self) -> None:
        report = make_report(
            (
                make_device_audit(
                    (
                        make_finding("R-1", "critical", STATUS_FAIL),
                        make_finding("R-2", "high", STATUS_FAIL),
                        make_finding("R-3", "low", STATUS_FAIL),
                        make_finding("R-4", "critical", STATUS_PASS),
                    )
                ),
            )
        )
        self.assertEqual(report.failures_at_or_above("critical"), 1)
        self.assertEqual(report.failures_at_or_above("high"), 2)
        self.assertEqual(report.failures_at_or_above("low"), 3)
        self.assertEqual(report.failures_at_or_above("any"), 3)
        self.assertEqual(report.failures_at_or_above("none"), 0)
        with self.assertRaises(ValueError):
            report.failures_at_or_above("urgent")


class AuditVaultTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.vault = Vault.initialize(Path(self._temporary.name) / "vault")

    def test_audit_vault_audits_latest_revisions_sorted_by_device(self) -> None:
        self.vault.snapshot(
            DeviceInfo(name="core-sw-01", vendor="cisco-ios", site="porto-lab"),
            COMPLIANT_CISCO,
            captured_at="2026-01-01T00:00:00Z",
        )
        self.vault.snapshot(
            DeviceInfo(name="edge-rtr-01", vendor="cisco-ios", site="porto-lab"),
            FAILING_CISCO,
            captured_at="2026-01-01T00:00:00Z",
        )
        report = audit_vault(self.vault, generated_at="2026-01-02T00:00:00Z")
        self.assertEqual(report.generated_at, "2026-01-02T00:00:00Z")
        self.assertEqual([audit.device.name for audit in report.device_audits], ["core-sw-01", "edge-rtr-01"])
        self.assertEqual(report.rule_definitions, len(builtin_rules()))
        self.assertEqual(report.custom_rule_count, 0)
        self.assertEqual(report.device_audits[0].revision, 1)
        self.assertEqual(report.device_audits[0].status, STATUS_PASS)
        self.assertEqual(report.device_audits[1].status, STATUS_FAIL)
        self.assertEqual(report.device_audits[1].critical_failures, 2)
        self.assertGreaterEqual(report.total_failed, 5)

    def test_audit_vault_can_audit_a_subset_of_devices(self) -> None:
        for name in ("core-sw-01", "edge-rtr-01"):
            self.vault.snapshot(
                DeviceInfo(name=name, vendor="cisco-ios"),
                COMPLIANT_CISCO if name == "core-sw-01" else FAILING_CISCO,
                captured_at="2026-01-01T00:00:00Z",
            )
        report = audit_vault(self.vault, devices=("edge-rtr-01",))
        self.assertEqual(len(report.device_audits), 1)
        self.assertEqual(report.device_audits[0].device.name, "edge-rtr-01")

    def test_audit_vault_rejects_unknown_devices(self) -> None:
        with self.assertRaises(UnknownDeviceError):
            audit_vault(self.vault, devices=("missing",))

    def test_audit_vault_on_empty_vault_returns_empty_pass_report(self) -> None:
        report = audit_vault(self.vault, generated_at="2026-01-02T00:00:00Z")
        self.assertEqual(report.device_audits, ())
        self.assertEqual(report.total_failed, 0)
        self.assertEqual(report.status, STATUS_PASS)

    def test_audit_vault_includes_custom_rules(self) -> None:
        custom = Rule(
            id="ORG-001",
            title="Organisation NTP range",
            severity="low",
            vendors=("cisco-ios",),
            must_match=(r"^\s*ntp server 198\.51\.100\.",),
            source="custom.json",
        )
        self.vault.snapshot(
            DeviceInfo(name="core-sw-01", vendor="cisco-ios"),
            COMPLIANT_CISCO,
            captured_at="2026-01-01T00:00:00Z",
        )
        rules = tuple(builtin_rules()) + (custom,)
        report = audit_vault(self.vault, rules=rules, generated_at="2026-01-02T00:00:00Z")
        self.assertEqual(report.rule_definitions, 22)
        self.assertEqual(report.custom_rule_count, 1)
        finding = next(
            finding
            for finding in report.device_audits[0].findings
            if finding.rule_id == "ORG-001"
        )
        self.assertEqual(finding.status, STATUS_FAIL)

    def test_duplicate_devices_in_argument_are_audited_once(self) -> None:
        self.vault.snapshot(
            DeviceInfo(name="core-sw-01", vendor="cisco-ios"),
            COMPLIANT_CISCO,
            captured_at="2026-01-01T00:00:00Z",
        )
        report = audit_vault(self.vault, devices=("core-sw-01", "CORE-SW-01"))
        self.assertEqual(len(report.device_audits), 1)


if __name__ == "__main__":
    unittest.main()

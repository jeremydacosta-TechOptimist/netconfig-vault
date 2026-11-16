"""End-to-end CLI tests run through a subprocess with PYTHONPATH preserved."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
BASELINE_DIR = REPO_ROOT / "examples" / "lab-configs" / "baseline"
DRIFT_DIR = REPO_ROOT / "examples" / "lab-configs" / "drift"
RULE_FILE = REPO_ROOT / "examples" / "rules" / "lab-baseline.json"

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
MEDIUM_FAIL_CISCO = COMPLIANT_CISCO.replace("ntp server 203.0.113.10\n", "")
CRITICAL_CISCO = (
    "hostname test-edge\n"
    "line vty 0 4\n"
    " transport input all\n"
    "snmp-server community public RO\n"
    "ip http server\n"
)


def run_cli(
    *args: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m netvault`` with the repository source on PYTHONPATH."""
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(SRC_DIR) + (os.pathsep + existing if existing else "")
    environment["PYTHONIOENCODING"] = "utf-8"
    if env:
        environment.update(env)
    return subprocess.run(
        [sys.executable, "-m", "netvault", *args],
        cwd=str(REPO_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


def write_config(directory: Path, filename: str, body: str, vendor: str = "cisco-ios") -> Path:
    """Write a configuration export fixture."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(f"# vendor: {vendor}\n{body}", encoding="utf-8")
    return path


class CliHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.vault = self.root / "vault"


class HelpAndUsageTest(CliHarness):
    def test_help_lists_every_subcommand_and_exit_codes(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        for command in ("init", "snapshot", "devices", "history", "diff", "audit", "report"):
            self.assertIn(command, result.stdout)
        self.assertIn("exit codes", result.stdout)
        self.assertIn("NETVAULT_VAULT", result.stdout)

    def test_version_flag_prints_version(self) -> None:
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("netvault 1.0.0", result.stdout)

    def test_unknown_command_returns_usage_error(self) -> None:
        result = run_cli("frobnicate")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)

    def test_missing_subcommand_returns_usage_error(self) -> None:
        result = run_cli()
        self.assertEqual(result.returncode, 2)

    def test_missing_required_argument_returns_usage_error(self) -> None:
        result = run_cli("history")
        self.assertEqual(result.returncode, 2)

    def test_invalid_revision_returns_usage_error(self) -> None:
        result = run_cli("diff", "core-sw-01", "abc", "2")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid revision", result.stderr)

    def test_invalid_context_returns_usage_error(self) -> None:
        result = run_cli("diff", "core-sw-01", "1", "2", "--context", "-1")
        self.assertEqual(result.returncode, 2)

    def test_missing_vault_returns_runtime_error(self) -> None:
        result = run_cli("--vault", str(self.vault), "devices")
        self.assertEqual(result.returncode, 1)
        self.assertIn("error:", result.stderr)
        self.assertIn("netvault init", result.stderr)

    def test_cli_entry_point_is_importable_and_callable(self) -> None:
        environment = os.environ.copy()
        existing = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = str(SRC_DIR) + (os.pathsep + existing if existing else "")
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from netvault.cli import main; raise SystemExit(main(['--version']))",
            ],
            cwd=str(REPO_ROOT),
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("netvault 1.0.0", result.stdout)


class SnapshotWorkflowTest(CliHarness):
    def test_init_snapshot_list_and_history(self) -> None:
        init = run_cli("--vault", str(self.vault), "init")
        self.assertEqual(init.returncode, 0)
        self.assertIn("Vault ready at:", init.stdout)
        self.assertIn("Schema version: 1", init.stdout)
        self.assertTrue((self.vault / "vault.db").is_file())

        first = run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        self.assertEqual(first.returncode, 0)
        self.assertIn("3 new revision(s), 0 unchanged, 0 error(s)", first.stdout)
        self.assertIn("core-sw-01 (Cisco IOS): revision 1 created", first.stdout)

        second = run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        self.assertEqual(second.returncode, 0)
        self.assertIn("0 new revision(s), 3 unchanged, 0 error(s)", second.stdout)
        self.assertIn("unchanged (identical to latest)", second.stdout)

        devices = run_cli("--vault", str(self.vault), "devices")
        self.assertEqual(devices.returncode, 0)
        self.assertIn("core-sw-01", devices.stdout)
        self.assertIn("access-aruba-01", devices.stdout)
        self.assertIn("Aruba / HP", devices.stdout)
        self.assertIn("LAST SNAPSHOT", devices.stdout)

        history = run_cli("--vault", str(self.vault), "history", "core-sw-01")
        self.assertEqual(history.returncode, 0)
        self.assertIn("History for core-sw-01 (Cisco IOS, site: porto-lab)", history.stdout)
        self.assertIn("REV", history.stdout)
        self.assertIn("1", history.stdout)

    def test_init_is_idempotent(self) -> None:
        self.assertEqual(run_cli("--vault", str(self.vault), "init").returncode, 0)
        run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        again = run_cli("--vault", str(self.vault), "init")
        self.assertEqual(again.returncode, 0)
        self.assertIn("Devices in vault: 3", again.stdout)

    def test_snapshot_accepts_a_note(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        snapshot_dir = self.root / "configs"
        write_config(snapshot_dir, "core-sw-01.cfg", COMPLIANT_CISCO)
        result = run_cli(
            "--vault", str(self.vault), "snapshot", str(snapshot_dir), "--note", "change window 42"
        )
        self.assertEqual(result.returncode, 0)
        history = run_cli("--vault", str(self.vault), "history", "core-sw-01")
        self.assertIn("change window 42", history.stdout)

    def test_dry_run_does_not_create_a_vault(self) -> None:
        result = run_cli(
            "--vault", str(self.vault), "snapshot", str(BASELINE_DIR), "--dry-run"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Dry run - 3 configuration(s) collected", result.stdout)
        self.assertFalse(self.vault.exists())

    def test_missing_collection_directory_returns_runtime_failure(self) -> None:
        result = run_cli(
            "--vault", str(self.vault), "snapshot", str(self.root / "missing-directory")
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("configuration directory not found", result.stderr)

    def test_empty_collection_directory_returns_runtime_failure(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        result = run_cli("--vault", str(self.vault), "snapshot", str(empty))
        self.assertEqual(result.returncode, 1)
        self.assertIn("no configuration files found", result.stderr)

    def test_invalid_configuration_is_reported_but_valid_ones_are_stored(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        configs = self.root / "configs"
        write_config(configs, "good.cfg", COMPLIANT_CISCO)
        (configs / "bad.cfg").write_text("not a network configuration\n", encoding="utf-8")
        result = run_cli("--vault", str(self.vault), "snapshot", str(configs))
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot determine the device vendor", result.stderr)
        devices = run_cli("--vault", str(self.vault), "devices")
        self.assertIn("good", devices.stdout)

    def test_history_limit_returns_newest_revisions_only(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        run_cli("--vault", str(self.vault), "snapshot", str(DRIFT_DIR))
        result = run_cli("--vault", str(self.vault), "history", "core-sw-01", "--limit", "1")
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.splitlines()
        separator = next(
            index
            for index, line in enumerate(lines)
            if line.strip() and set(line.strip()) <= {"-", " "}
        )
        self.assertEqual(len(lines) - separator - 1, 1)

    def test_history_unknown_device_returns_runtime_failure(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        result = run_cli("--vault", str(self.vault), "history", "missing")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown device", result.stderr)

    def test_vault_can_be_selected_with_environment_variable(self) -> None:
        result = run_cli("init", env={"NETVAULT_VAULT": str(self.vault)})
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.vault / "vault.db").is_file())


class ChangeAndComplianceWorkflowTest(CliHarness):
    def test_diff_audit_and_report_end_to_end(self) -> None:
        for args in (
            ("--vault", str(self.vault), "init"),
            ("--vault", str(self.vault), "snapshot", str(BASELINE_DIR)),
            ("--vault", str(self.vault), "snapshot", str(DRIFT_DIR)),
        ):
            result = run_cli(*args)
            self.assertEqual(result.returncode, 0, msg=result.stderr)

        diff = run_cli(
            "--vault", str(self.vault), "diff", "core-sw-01", "1", "2", "--context", "1"
        )
        self.assertEqual(diff.returncode, 0)
        self.assertIn("Change summary - core-sw-01 (revision 1 -> 2)", diff.stdout)
        self.assertIn("interfaces added: GigabitEthernet0/5", diff.stdout)
        self.assertIn("@@", diff.stdout)

        audit = run_cli(
            "--vault",
            str(self.vault),
            "audit",
            "--rules",
            str(RULE_FILE),
        )
        self.assertEqual(audit.returncode, 1)
        self.assertIn("Compliance audit - 3 device(s)", audit.stdout)
        self.assertIn("2 custom", audit.stdout)
        self.assertIn("overall: FAIL", audit.stdout)
        self.assertIn("FAIL critical", audit.stdout)
        self.assertIn("CISCO-TELNET-001", audit.stdout)

        relaxed = run_cli(
            "--vault", str(self.vault), "audit", "--rules", str(RULE_FILE), "--fail-on", "none"
        )
        self.assertEqual(relaxed.returncode, 0)

        report_path = self.root / "estate.md"
        report = run_cli(
            "--vault",
            str(self.vault),
            "report",
            "--rules",
            str(RULE_FILE),
            "--format",
            "md",
            "--out",
            str(report_path),
        )
        self.assertEqual(report.returncode, 0)
        self.assertIn("Wrote estate report (md)", report.stdout)
        self.assertIn("# netvault estate report", report_path.read_text(encoding="utf-8"))

        audit_path = self.root / "audit.html"
        audit_report = run_cli(
            "--vault",
            str(self.vault),
            "audit",
            "--rules",
            str(RULE_FILE),
            "--format",
            "html",
            "--out",
            str(audit_path),
        )
        self.assertEqual(audit_report.returncode, 1)
        html = audit_path.read_text(encoding="utf-8")
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertNotIn("<script", html.lower())

    def test_audit_of_compliant_configuration_exits_zero(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        configs = self.root / "configs"
        write_config(configs, "core-sw-01.cfg", COMPLIANT_CISCO)
        run_cli("--vault", str(self.vault), "snapshot", str(configs))
        result = run_cli("--vault", str(self.vault), "audit")
        self.assertEqual(result.returncode, 0)
        self.assertIn("overall: PASS", result.stdout)

    def test_audit_fail_on_threshold_controls_exit_code(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        configs = self.root / "configs"
        write_config(configs, "core-sw-01.cfg", MEDIUM_FAIL_CISCO)
        run_cli("--vault", str(self.vault), "snapshot", str(configs))
        self.assertEqual(run_cli("--vault", str(self.vault), "audit").returncode, 0)
        self.assertEqual(
            run_cli("--vault", str(self.vault), "audit", "--fail-on", "high").returncode,
            0,
        )
        self.assertEqual(
            run_cli("--vault", str(self.vault), "audit", "--fail-on", "any").returncode,
            1,
        )
        self.assertEqual(
            run_cli("--vault", str(self.vault), "audit", "--fail-on", "none").returncode,
            0,
        )

    def test_audit_critical_findings_return_one(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        configs = self.root / "configs"
        write_config(configs, "edge-rtr-01.cfg", CRITICAL_CISCO)
        run_cli("--vault", str(self.vault), "snapshot", str(configs))
        result = run_cli("--vault", str(self.vault), "audit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("critical", result.stdout)

    def test_diff_latest_keyword_and_identical_revisions(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        configs = self.root / "configs"
        write_config(configs, "core-sw-01.cfg", COMPLIANT_CISCO)
        run_cli("--vault", str(self.vault), "snapshot", str(configs))
        write_config(configs, "core-sw-01.cfg", COMPLIANT_CISCO + "ip route 0.0.0.0 0.0.0.0 198.51.100.1\n")
        run_cli("--vault", str(self.vault), "snapshot", str(configs))

        latest = run_cli("--vault", str(self.vault), "diff", "core-sw-01", "1", "latest")
        self.assertEqual(latest.returncode, 0)
        self.assertIn("revision 1 -> 2", latest.stdout)

        identical = run_cli("--vault", str(self.vault), "diff", "core-sw-01", "1", "1")
        self.assertEqual(identical.returncode, 0)
        self.assertIn("No changes between revision 1 and revision 1.", identical.stdout)

    def test_diff_summary_only_omits_the_unified_diff(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        run_cli("--vault", str(self.vault), "snapshot", str(DRIFT_DIR))
        result = run_cli(
            "--vault", str(self.vault), "diff", "core-sw-01", "1", "2", "--summary-only"
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Change summary - core-sw-01 (revision 1 -> 2)", result.stdout)
        self.assertNotIn("@@", result.stdout)
        self.assertNotIn("--- core-sw-01 revision", result.stdout)

    def test_diff_unknown_revision_returns_runtime_failure(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        result = run_cli("--vault", str(self.vault), "diff", "core-sw-01", "1", "99")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no revision 99", result.stderr)

    def test_audit_with_missing_rule_file_returns_runtime_failure(self) -> None:
        run_cli("--vault", str(self.vault), "init")
        run_cli("--vault", str(self.vault), "snapshot", str(BASELINE_DIR))
        result = run_cli(
            "--vault", str(self.vault), "audit", "--rules", str(self.root / "missing.json")
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()

"""Compliance evaluation and audit aggregation.

Rules are evaluated line by line against the normalized configuration of a
device. Each applicable rule produces one ``PASS``, ``FAIL`` or ``SKIP``
finding, failures carry enough detail to explain the check, and each device
gets a severity-weighted compliance score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .baselines import builtin_rules
from .models import (
    SEVERITIES,
    SEVERITY_ORDER,
    SEVERITY_WEIGHTS,
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    DeviceInfo,
    SnapshotRecord,
)
from .normalize import normalize_config
from .rules import Rule
from .store import UnknownDeviceError, Vault, utc_now_iso

FAIL_ON_CHOICES: tuple[str, ...] = ("critical", "high", "medium", "low", "any", "none")
_SNIPPET_LIMIT = 100


@dataclass(frozen=True)
class Finding:
    """Result of evaluating one rule against one device configuration."""

    rule_id: str
    title: str
    severity: str
    status: str
    details: tuple[str, ...] = ()
    remediation: str = ""


@dataclass(frozen=True)
class DeviceAudit:
    """All compliance findings for one revision of one device."""

    device: DeviceInfo
    revision: int
    digest: str
    captured_at: str
    findings: tuple[Finding, ...]

    @property
    def passed(self) -> int:
        """Number of passing checks."""
        return sum(1 for finding in self.findings if finding.status == STATUS_PASS)

    @property
    def failed(self) -> int:
        """Number of failing checks."""
        return sum(1 for finding in self.findings if finding.status == STATUS_FAIL)

    @property
    def skipped(self) -> int:
        """Number of skipped checks."""
        return sum(1 for finding in self.findings if finding.status == STATUS_SKIP)

    @property
    def failures(self) -> tuple[Finding, ...]:
        """Failing checks ordered by severity, then rule id."""
        failing = [finding for finding in self.findings if finding.status == STATUS_FAIL]
        return tuple(
            sorted(
                failing,
                key=lambda finding: (SEVERITY_ORDER[finding.severity], finding.rule_id),
            )
        )

    @property
    def critical_failures(self) -> int:
        """Number of failing checks with critical severity."""
        return sum(1 for finding in self.failures if finding.severity == "critical")

    @property
    def weighted_score(self) -> float:
        """Severity-weighted compliance score in the range 0-100."""
        return _weighted_score(self.findings)

    @property
    def status(self) -> str:
        """``PASS`` when no check failed, otherwise ``FAIL``."""
        return STATUS_PASS if self.failed == 0 else STATUS_FAIL


@dataclass(frozen=True)
class AuditReport:
    """Compliance audit across a set of devices in a vault."""

    vault_path: str
    generated_at: str
    device_audits: tuple[DeviceAudit, ...]
    rule_definitions: int
    custom_rule_count: int

    @property
    def builtin_rule_count(self) -> int:
        """Number of built-in rule definitions considered in this audit."""
        return max(self.rule_definitions - self.custom_rule_count, 0)

    @property
    def total_passed(self) -> int:
        """Total passing checks across all audited devices."""
        return sum(audit.passed for audit in self.device_audits)

    @property
    def total_failed(self) -> int:
        """Total failing checks across all audited devices."""
        return sum(audit.failed for audit in self.device_audits)

    @property
    def total_skipped(self) -> int:
        """Total skipped checks across all audited devices."""
        return sum(audit.skipped for audit in self.device_audits)

    @property
    def critical_failures(self) -> int:
        """Critical failing checks across all audited devices."""
        return sum(audit.critical_failures for audit in self.device_audits)

    @property
    def failures_by_severity(self) -> Mapping[str, int]:
        """Failing check counts keyed by severity, ordered critical to low."""
        counts = {severity: 0 for severity in SEVERITIES}
        for audit in self.device_audits:
            for finding in audit.findings:
                if finding.status == STATUS_FAIL:
                    counts[finding.severity] += 1
        return counts

    @property
    def overall_weighted_score(self) -> float:
        """Severity-weighted compliance score across all audited devices."""
        findings = [finding for audit in self.device_audits for finding in audit.findings]
        return _weighted_score(findings)

    @property
    def status(self) -> str:
        """``PASS`` when no check failed, otherwise ``FAIL``."""
        return STATUS_PASS if self.total_failed == 0 else STATUS_FAIL

    def failures_at_or_above(self, threshold: str) -> int:
        """Count failures at or above *threshold* (plus ``any`` and ``none``)."""
        if threshold == "none":
            return 0
        if threshold == "any":
            return self.total_failed
        if threshold not in SEVERITIES:
            raise ValueError(
                f"invalid failure threshold {threshold!r}; expected one of: "
                f"{', '.join(FAIL_ON_CHOICES)}"
            )
        minimum_weight = SEVERITY_WEIGHTS[threshold]
        return sum(
            1
            for audit in self.device_audits
            for finding in audit.findings
            if finding.status == STATUS_FAIL
            and SEVERITY_WEIGHTS[finding.severity] >= minimum_weight
        )


def _weighted_score(findings: Iterable[Finding]) -> float:
    """Score findings as passed weight divided by applied weight, in percent."""
    applied = 0
    passed = 0
    for finding in findings:
        if finding.status == STATUS_SKIP:
            continue
        weight = SEVERITY_WEIGHTS[finding.severity]
        applied += weight
        if finding.status == STATUS_PASS:
            passed += weight
    if applied == 0:
        return 0.0
    return round(100.0 * passed / applied, 1)


def _snippet(line: str, limit: int = _SNIPPET_LIMIT) -> str:
    """Return a single-line excerpt of a configuration line."""
    text = line.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _first_match(
    lines: Sequence[str], patterns: Sequence[str]
) -> tuple[str, int, str] | None:
    """Return the first ``(pattern, line number, line)`` match, if any."""
    for pattern in patterns:
        for number, line in enumerate(lines, start=1):
            if re.search(pattern, line):
                return pattern, number, line
    return None


def _all_matches(lines: Sequence[str], pattern: str) -> list[tuple[int, str]]:
    """Return every ``(line number, line)`` matching *pattern*."""
    return [
        (number, line) for number, line in enumerate(lines, start=1) if re.search(pattern, line)
    ]


def evaluate_config(config: str, rules: Sequence[Rule], *, vendor: str) -> tuple[Finding, ...]:
    """Evaluate *rules* against one configuration and return findings.

    Only rules scoped to *vendor* are evaluated. An empty configuration makes
    every applicable rule ``SKIP`` instead of failing.
    """
    applicable = [rule for rule in rules if vendor in rule.vendors]
    normalized = normalize_config(config)
    if not normalized:
        return tuple(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                status=STATUS_SKIP,
                details=("empty configuration",),
                remediation=rule.remediation,
            )
            for rule in applicable
        )
    lines = normalized.splitlines()
    findings: list[Finding] = []
    for rule in applicable:
        skip_match = _first_match(lines, rule.skip_if)
        if skip_match is not None:
            _, number, line = skip_match
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    status=STATUS_SKIP,
                    details=(f"skip condition matched line {number}: {_snippet(line)}",),
                    remediation=rule.remediation,
                )
            )
            continue
        details: list[str] = []
        for pattern in rule.must_match:
            if _first_match(lines, (pattern,)) is None:
                details.append(f"missing required pattern: {pattern}")
        for pattern in rule.must_not_match:
            matches = _all_matches(lines, pattern)
            for number, line in matches[:3]:
                details.append(f"forbidden pattern matched line {number}: {_snippet(line)}")
            if len(matches) > 3:
                details.append(f"forbidden pattern {pattern} matched {len(matches)} lines")
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                status=STATUS_FAIL if details else STATUS_PASS,
                details=tuple(details),
                remediation=rule.remediation,
            )
        )
    return tuple(findings)


def audit_device(
    info: DeviceInfo,
    record: SnapshotRecord,
    config: str,
    rules: Sequence[Rule],
) -> DeviceAudit:
    """Audit one device revision against *rules*."""
    findings = evaluate_config(config, rules, vendor=info.vendor)
    return DeviceAudit(
        device=info,
        revision=record.revision,
        digest=record.digest,
        captured_at=record.captured_at,
        findings=findings,
    )


def audit_vault(
    vault: Vault,
    *,
    rules: Sequence[Rule] | None = None,
    devices: Sequence[str] | None = None,
    generated_at: str | None = None,
) -> AuditReport:
    """Audit the latest revision of devices stored in *vault*.

    Args:
        vault: An opened vault.
        rules: Rule set to evaluate; defaults to the built-in baselines.
        devices: Device names to audit; defaults to every device in the vault.
        generated_at: Report timestamp; defaults to the current UTC time.
    """
    rule_list = tuple(builtin_rules()) if rules is None else tuple(rules)
    if not rule_list:
        raise ValueError("at least one compliance rule is required")
    unique_ids = {rule.id for rule in rule_list}
    custom_ids = {rule.id for rule in rule_list if rule.source != "built-in"}

    summaries = vault.list_devices()
    by_name = {summary.name.lower(): summary for summary in summaries}
    if devices is None:
        selected = summaries
    else:
        selected = []
        seen: set[str] = set()
        for name in devices:
            key = name.lower()
            if key in seen:
                continue
            summary = by_name.get(key)
            if summary is None:
                raise UnknownDeviceError(f"unknown device: {name}")
            seen.add(key)
            selected.append(summary)

    audits: list[DeviceAudit] = []
    for summary in selected:
        record, content = vault.read_revision(summary.name, summary.latest_revision)
        info = DeviceInfo(
            name=summary.name,
            vendor=summary.vendor,
            site=summary.site,
            role=summary.role,
        )
        audits.append(audit_device(info, record, content, rule_list))
    return AuditReport(
        vault_path=vault.display_path,
        generated_at=generated_at or utc_now_iso(),
        device_audits=tuple(audits),
        rule_definitions=len(unique_ids),
        custom_rule_count=len(custom_ids),
    )

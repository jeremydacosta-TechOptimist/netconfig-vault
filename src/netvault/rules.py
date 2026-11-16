"""Compliance rule model, JSON rule-file loading and rule merging.

A rule is a declarative, line-oriented check against a normalized device
configuration. Patterns are regular expressions evaluated with
``re.search`` against one configuration line at a time (``re.MULTILINE`` is
therefore unnecessary). See ``docs/rules.md`` for the file format.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .models import SUPPORTED_VENDORS, validate_severity, validate_vendor

RULE_FIELDS = frozenset(
    {
        "id",
        "title",
        "severity",
        "vendors",
        "must_match",
        "must_not_match",
        "skip_if",
        "remediation",
    }
)

_RULE_FILE_KEYS = frozenset({"name", "description", "rules"})
_RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class RuleError(ValueError):
    """Raised when a compliance rule or rule file is malformed."""


@dataclass(frozen=True)
class Rule:
    """One declarative compliance check.

    Attributes:
        id: Stable identifier used in reports and for rule overrides.
        title: Human readable check description.
        severity: One of ``critical``, ``high``, ``medium``, ``low``.
        vendors: Vendors the rule applies to (defaults to all supported ones).
        must_match: Patterns of which at least one line must match, for every
            pattern in the tuple.
        must_not_match: Patterns that must not match any configuration line.
        skip_if: Patterns that mark the check as ``SKIP`` when matched.
        remediation: Short guidance shown for failing checks.
        source: ``built-in`` or the originating rule file name.
    """

    id: str
    title: str
    severity: str
    vendors: tuple[str, ...] = SUPPORTED_VENDORS
    must_match: tuple[str, ...] = ()
    must_not_match: tuple[str, ...] = ()
    skip_if: tuple[str, ...] = ()
    remediation: str = ""
    source: str = "built-in"

    def __post_init__(self) -> None:
        rule_id = self.id.strip()
        if not _RULE_ID_PATTERN.match(rule_id):
            raise RuleError(
                f"invalid rule id {self.id!r}; use letters, digits, dots, dashes "
                "or underscores"
            )
        title = self.title.strip()
        if not title:
            raise RuleError(f"rule {rule_id}: title must not be empty")
        try:
            severity = validate_severity(self.severity)
        except ValueError as exc:
            raise RuleError(f"rule {rule_id}: {exc}") from exc

        vendors: list[str] = []
        for value in self.vendors:
            try:
                vendor = validate_vendor(value)
            except ValueError as exc:
                raise RuleError(f"rule {rule_id}: {exc}") from exc
            if vendor not in vendors:
                vendors.append(vendor)
        if not vendors:
            raise RuleError(f"rule {rule_id}: at least one vendor is required")

        if not self.must_match and not self.must_not_match:
            raise RuleError(
                f"rule {rule_id}: at least one must_match or must_not_match pattern "
                "is required"
            )
        for field_name, patterns in (
            ("must_match", self.must_match),
            ("must_not_match", self.must_not_match),
            ("skip_if", self.skip_if),
        ):
            for pattern in patterns:
                if not isinstance(pattern, str) or not pattern:
                    raise RuleError(f"rule {rule_id}: {field_name} patterns must be non-empty strings")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise RuleError(
                        f"rule {rule_id}: invalid regular expression {pattern!r}: {exc}"
                    ) from exc

        object.__setattr__(self, "id", rule_id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "vendors", tuple(vendors))
        object.__setattr__(self, "remediation", self.remediation.strip())
        object.__setattr__(self, "source", self.source.strip() or "built-in")


def _string_tuple(raw: Mapping[str, Any], field_name: str, *, rule_id: str) -> tuple[str, ...]:
    """Read a string-or-list-of-strings field from a rule mapping."""
    value = raw.get(field_name)
    if value is None:
        return ()
    if isinstance(value, str):
        items: list[Any] = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise RuleError(f"rule {rule_id}: {field_name} must be a string or a list of strings")
    result: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise RuleError(f"rule {rule_id}: {field_name} entries must be non-empty strings")
        result.append(item)
    return tuple(result)


def rule_from_mapping(raw: Mapping[str, Any], *, source: str) -> Rule:
    """Validate one rule definition from parsed JSON and build a :class:`Rule`."""
    if not isinstance(raw, Mapping):
        raise RuleError("each rule definition must be a JSON object")
    unknown = set(raw) - RULE_FIELDS
    if unknown:
        raise RuleError(f"unknown rule field(s): {', '.join(sorted(unknown))}")
    rule_id_value = raw.get("id")
    if not isinstance(rule_id_value, str) or not rule_id_value.strip():
        raise RuleError("each rule must have a non-empty string 'id'")
    rule_id = rule_id_value.strip()
    title_value = raw.get("title")
    if not isinstance(title_value, str) or not title_value.strip():
        raise RuleError(f"rule {rule_id}: a non-empty string 'title' is required")
    severity_value = raw.get("severity")
    if not isinstance(severity_value, str):
        raise RuleError(f"rule {rule_id}: a string 'severity' is required")
    remediation_value = raw.get("remediation", "")
    if not isinstance(remediation_value, str):
        raise RuleError(f"rule {rule_id}: 'remediation' must be a string")

    kwargs: dict[str, Any] = {
        "id": rule_id,
        "title": title_value,
        "severity": severity_value,
        "must_match": _string_tuple(raw, "must_match", rule_id=rule_id),
        "must_not_match": _string_tuple(raw, "must_not_match", rule_id=rule_id),
        "skip_if": _string_tuple(raw, "skip_if", rule_id=rule_id),
        "remediation": remediation_value,
        "source": source,
    }
    if "vendors" in raw:
        kwargs["vendors"] = _string_tuple(raw, "vendors", rule_id=rule_id)
    return Rule(**kwargs)


def load_rule_file(path: str | Path) -> tuple[Rule, ...]:
    """Load and validate a JSON rule file.

    The file may contain either a top-level list of rules or an object with a
    ``rules`` list (plus optional ``name`` and ``description`` keys).

    Raises:
        RuleError: when the JSON or a rule definition is invalid.
        OSError: when the file cannot be read.
    """
    file_path = Path(path)
    raw_text = file_path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuleError(f"{file_path.name}: invalid JSON: {exc}") from exc

    if isinstance(payload, Mapping):
        unknown = set(payload) - _RULE_FILE_KEYS
        if unknown:
            raise RuleError(f"{file_path.name}: unknown top-level key(s): {', '.join(sorted(unknown))}")
        raw_rules = payload.get("rules")
        if not isinstance(raw_rules, list):
            raise RuleError(f"{file_path.name}: expected a 'rules' list")
    elif isinstance(payload, list):
        raw_rules = payload
    else:
        raise RuleError(f"{file_path.name}: expected a JSON object or a list of rules")

    if not raw_rules:
        raise RuleError(f"{file_path.name}: the rule file contains no rules")

    rules: list[Rule] = []
    seen: set[str] = set()
    for raw_rule in raw_rules:
        rule = rule_from_mapping(raw_rule, source=file_path.name)
        if rule.id in seen:
            raise RuleError(f"{file_path.name}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)
    return tuple(rules)


def merge_rules(base: Sequence[Rule], extra: Sequence[Rule]) -> tuple[Rule, ...]:
    """Merge rule sequences, letting *extra* rules override same-id defaults.

    Overridden rules keep the position of the rule they replace, which keeps
    report ordering stable regardless of how many rule files are supplied.
    """
    merged: dict[str, Rule] = {}
    for rule in base:
        merged[rule.id] = rule
    for rule in extra:
        merged[rule.id] = rule
    return tuple(merged.values())

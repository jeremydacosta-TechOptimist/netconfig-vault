"""Built-in compliance baselines for Cisco IOS and Aruba/HP configurations.

The baselines are deliberately line oriented and conservative: each rule is a
small set of regular expressions covering common hardening checks (SSH-only
management, AAA, NTP, syslog, banners, no cleartext credentials). They are a
starting point for lab and lab-like environments, not a replacement for the
vendor hardening guide; see ``docs/rules.md``.
"""

from __future__ import annotations

from functools import lru_cache

from .rules import Rule


def _rule(
    rule_id: str,
    title: str,
    severity: str,
    vendor: str,
    *,
    must_match: tuple[str, ...] = (),
    must_not_match: tuple[str, ...] = (),
    skip_if: tuple[str, ...] = (),
    remediation: str,
) -> Rule:
    """Build one built-in rule scoped to a single vendor."""
    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        vendors=(vendor,),
        must_match=must_match,
        must_not_match=must_not_match,
        skip_if=skip_if,
        remediation=remediation,
        source="built-in",
    )


_CISCO_RULES: tuple[Rule, ...] = (
    _rule(
        "CISCO-SSH-001",
        "SSHv2 enabled for remote management",
        "high",
        "cisco-ios",
        must_match=(r"^ip ssh version 2\s*$",),
        remediation="Configure 'ip ssh version 2' and regenerate RSA keys if needed.",
    ),
    _rule(
        "CISCO-TELNET-001",
        "VTY transport restricted to SSH (no Telnet)",
        "critical",
        "cisco-ios",
        must_match=(r"^\s*transport input ssh\s*$",),
        must_not_match=(
            r"^\s*transport input\s+all\s*$",
            r"^\s*transport input\s+[^\n]*\btelnet\b",
        ),
        remediation="Set 'transport input ssh' on every VTY line and remove telnet/all.",
    ),
    _rule(
        "CISCO-PWD-001",
        "No cleartext enable or user passwords",
        "critical",
        "cisco-ios",
        must_not_match=(
            r"^\s*enable password\s+\S+",
            r"^\s*enable secret 0\s+\S+",
            r"^\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+password\s+0\s+\S+",
        ),
        remediation="Remove cleartext passwords; use 'enable secret 9' and username secrets.",
    ),
    _rule(
        "CISCO-NTP-001",
        "NTP servers configured",
        "medium",
        "cisco-ios",
        must_match=(r"^\s*ntp server \S+",),
        remediation="Configure at least one 'ntp server <address>' entry.",
    ),
    _rule(
        "CISCO-LOG-001",
        "Remote syslog server configured",
        "medium",
        "cisco-ios",
        must_match=(r"^\s*logging\s+(?:host\s+)?(?:\d{1,3}\.){3}\d{1,3}",),
        remediation="Add 'logging host <collector>' (or 'logging <collector>' on older IOS).",
    ),
    _rule(
        "CISCO-BANNER-001",
        "Login banner configured",
        "medium",
        "cisco-ios",
        must_match=(r"^\s*banner\s+(?:motd|login)\s+(?:\^C|\^|#)\s*\S{8,}",),
        remediation="Add a MOTD or login banner with a non-empty authorised-use message.",
    ),
    _rule(
        "CISCO-AUTH-001",
        "AAA new-model enabled",
        "high",
        "cisco-ios",
        must_match=(r"^aaa new-model\s*$",),
        remediation="Enable AAA with 'aaa new-model' before configuring authentication lists.",
    ),
    _rule(
        "CISCO-AUTH-002",
        "AAA login authentication list configured",
        "high",
        "cisco-ios",
        must_match=(r"^\s*aaa authentication login\s+\S+(?:\s+\S+)+",),
        remediation="Define 'aaa authentication login <list> <methods>' for console and VTY access.",
    ),
    _rule(
        "CISCO-HTTP-001",
        "Cleartext HTTP management server disabled",
        "high",
        "cisco-ios",
        must_not_match=(r"^\s*ip http server\s*$",),
        remediation="Remove 'ip http server'; use 'ip http secure-server' with local authentication.",
    ),
    _rule(
        "CISCO-SNMP-001",
        "No default SNMP community strings",
        "critical",
        "cisco-ios",
        must_not_match=(r'^\s*snmp-server community\s+"?(?:public|private)"?\b',),
        remediation="Replace public/private community strings with unique, restricted communities.",
    ),
    _rule(
        "CISCO-VLAN-001",
        "Access ports not assigned to VLAN 1",
        "low",
        "cisco-ios",
        must_not_match=(r"^\s*switchport access vlan 1\s*$",),
        remediation="Move access ports to a dedicated VLAN instead of the default VLAN 1.",
    ),
)

_ARUBA_RULES: tuple[Rule, ...] = (
    _rule(
        "ARUBA-SSH-001",
        "SSH server enabled",
        "high",
        "aruba",
        must_match=(r"^\s*ip ssh\s*$",),
        must_not_match=(r"^\s*no ip ssh\s*$",),
        remediation="Enable SSH with 'ip ssh' and generate host keys if they are missing.",
    ),
    _rule(
        "ARUBA-TELNET-001",
        "Telnet server disabled",
        "critical",
        "aruba",
        must_match=(r"^\s*no telnet-server\s*$",),
        remediation="Disable the Telnet server explicitly with 'no telnet-server'.",
    ),
    _rule(
        "ARUBA-PWD-001",
        "No plaintext local passwords",
        "critical",
        "aruba",
        must_not_match=(r"^\s*password\s+(?:manager|operator)\s+plaintext\s+\S+",),
        remediation="Remove 'password ... plaintext' entries and set credentials through the CLI prompt.",
    ),
    _rule(
        "ARUBA-NTP-001",
        "NTP servers configured",
        "medium",
        "aruba",
        must_match=(r"^\s*ntp server\s+(?:priority\s+\d+\s+)?\S+",),
        remediation="Configure at least one 'ntp server' entry, preferably with priorities.",
    ),
    _rule(
        "ARUBA-LOG-001",
        "Remote syslog server configured",
        "medium",
        "aruba",
        must_match=(r"^\s*logging\s+(?:\d{1,3}\.){3}\d{1,3}\s*$",),
        remediation="Add 'logging <collector-ip>' to forward events to the syslog collector.",
    ),
    _rule(
        "ARUBA-BANNER-001",
        "Login banner configured",
        "medium",
        "aruba",
        must_match=(r'^\s*banner motd\s+(?:"[^"\n]{8,}"|\S{8,})',),
        remediation="Add a MOTD banner with a non-empty authorised-use message.",
    ),
    _rule(
        "ARUBA-AUTH-001",
        "AAA authentication configured",
        "high",
        "aruba",
        must_match=(r"^\s*aaa authentication\s+\S+",),
        remediation="Configure 'aaa authentication ...' for login and enable access.",
    ),
    _rule(
        "ARUBA-WEB-001",
        "Cleartext web management disabled",
        "high",
        "aruba",
        must_not_match=(r"^\s*web-management\s+plaintext\s*$",),
        skip_if=(r"^\s*no web-management\s*$",),
        remediation="Remove 'web-management plaintext' and keep only 'web-management ssl'.",
    ),
    _rule(
        "ARUBA-SNMP-001",
        "No default SNMP community strings",
        "critical",
        "aruba",
        must_not_match=(r'^\s*snmp-server community\s+"?(?:public|private)"?\b',),
        remediation="Replace public/private community strings with unique, restricted communities.",
    ),
    _rule(
        "ARUBA-STP-001",
        "Spanning Tree enabled",
        "medium",
        "aruba",
        must_match=(r"^\s*spanning-tree\s*$",),
        remediation="Enable spanning tree with 'spanning-tree' (and matching config name/revision).",
    ),
)


@lru_cache(maxsize=1)
def builtin_rules() -> tuple[Rule, ...]:
    """Return every built-in rule, Cisco first then Aruba."""
    return _CISCO_RULES + _ARUBA_RULES


def rules_for_vendor(vendor: str) -> tuple[Rule, ...]:
    """Return the built-in rules that apply to *vendor*."""
    return tuple(rule for rule in builtin_rules() if vendor in rule.vendors)

# Compliance rules and baselines

netvault ships two declarative baselines (Cisco IOS and Aruba / HP) and lets you
layer site-specific JSON rules on top of them. This page documents the rule
model, the evaluation semantics and every built-in check.

## Evaluation model

A rule is a line-oriented regular-expression check against the normalized
configuration of a device. Normalization strips volatile header lines, trailing
whitespace and CRLF line endings before evaluation, so rules never see
configuration timestamps. Each applicable rule produces exactly one finding:

| Status | Meaning |
| --- | --- |
| `PASS` | every `must_match` pattern matched and no `must_not_match` pattern matched |
| `FAIL` | at least one required pattern is missing, or at least one forbidden pattern matched |
| `SKIP` | the rule does not apply: empty configuration or a `skip_if` condition matched |

Patterns are evaluated with `re.search` against a single configuration line, so
`^` and `$` anchor to the line and patterns cannot span multiple lines. Rules
declared for one vendor are silently filtered out for devices of another vendor;
they do not appear as `SKIP` rows in that device's findings.

### Compliance score

Each device receives a severity-weighted score:

| Severity | Weight |
| --- | --- |
| critical | 10 |
| high | 5 |
| medium | 3 |
| low | 1 |

`score = 100 * passed weight / (passed weight + failed weight)`, with skipped
checks excluded. A device status is `FAIL` as soon as one check fails. The
`audit` command exits with code `1` when a finding at or above `--fail-on`
(default: `critical`) exists, so it can gate a change pipeline.

## Rule file format

`audit` and `report` accept one or more `--rules FILE` arguments. A rule file is
JSON containing either a top-level list of rules or an object with a `rules`
list:

```json
{
  "name": "lab-baseline",
  "description": "Site-specific checks layered on top of the built-in baselines.",
  "rules": [
    {
      "id": "LAB-LOG-001",
      "title": "All devices log to the lab syslog collector",
      "severity": "high",
      "vendors": ["cisco-ios", "aruba"],
      "must_match": ["^\\s*logging (?:host )?203\\.0\\.113\\.20\\s*$"],
      "must_not_match": [],
      "skip_if": [],
      "remediation": "Configure the lab syslog collector 203.0.113.20."
    }
  ]
}
```

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Unique rule identifier; letters, digits, dots, dashes, underscores. A custom rule with the same id as a built-in rule replaces it in place. |
| `title` | yes | Short human readable check description. |
| `severity` | yes | `critical`, `high`, `medium` or `low` (case-insensitive). |
| `vendors` | no | List of vendors (`cisco-ios`, `aruba`) or a single string. Defaults to all supported vendors. |
| `must_match` | one of | Pattern or list of patterns; every pattern must match at least one line. |
| `must_not_match` | one of | Pattern or list of patterns; no pattern may match any line. |
| `skip_if` | no | Pattern or list of patterns; the first match turns the finding into `SKIP`. |
| `remediation` | no | Guidance shown for failing checks in Markdown and HTML reports. |

`must_match` and `must_not_match` may both be present; at least one pattern is
required. Rule files are validated strictly: unknown keys, invalid regular
expressions, unknown vendors, duplicate ids and malformed JSON are rejected
with a clear error message and a `1` exit status.

## Built-in Cisco IOS baseline

| Rule id | Severity | Check | Remediation |
| --- | --- | --- | --- |
| `CISCO-SSH-001` | high | `ip ssh version 2` is configured | Enable SSHv2 |
| `CISCO-TELNET-001` | critical | VTY lines use `transport input ssh` and never `telnet`/`all` | Restrict VTY transport to SSH |
| `CISCO-PWD-001` | critical | No `enable password`, `enable secret 0` or `username ... password 0` | Use type 9 secrets |
| `CISCO-NTP-001` | medium | At least one `ntp server` | Configure NTP |
| `CISCO-LOG-001` | medium | A remote syslog server is configured | Add `logging host` |
| `CISCO-BANNER-001` | medium | A non-empty MOTD or login banner | Add a banner |
| `CISCO-AUTH-001` | high | `aaa new-model` is enabled | Enable AAA |
| `CISCO-AUTH-002` | high | An `aaa authentication login` list is defined | Define a login method list |
| `CISCO-HTTP-001` | high | `ip http server` is not enabled | Use `ip http secure-server` only |
| `CISCO-SNMP-001` | critical | No `public`/`private` SNMP communities | Use unique restricted communities |
| `CISCO-VLAN-001` | low | Access ports are not left in VLAN 1 | Move access ports to a user VLAN |

## Built-in Aruba / HP baseline

| Rule id | Severity | Check | Remediation |
| --- | --- | --- | --- |
| `ARUBA-SSH-001` | high | `ip ssh` is enabled | Enable SSH |
| `ARUBA-TELNET-001` | critical | `no telnet-server` is configured | Disable the Telnet server |
| `ARUBA-PWD-001` | critical | No `password ... plaintext` entries | Set credentials without plaintext |
| `ARUBA-NTP-001` | medium | At least one `ntp server` | Configure NTP |
| `ARUBA-LOG-001` | medium | A remote syslog server is configured | Add `logging <collector>` |
| `ARUBA-BANNER-001` | medium | A non-empty MOTD banner | Add a banner |
| `ARUBA-AUTH-001` | high | `aaa authentication` is configured | Configure AAA methods |
| `ARUBA-WEB-001` | high | `web-management plaintext` is not enabled | Keep only `web-management ssl` |
| `ARUBA-SNMP-001` | critical | No `public`/`private` SNMP communities | Use unique restricted communities |
| `ARUBA-STP-001` | medium | Spanning Tree is enabled | Enable `spanning-tree` |

## Limitations and honest advice

* The baselines encode common hardening checks, not every recommendation of a
  vendor hardening guide. Review the list against your own policy before using
  it to gate changes.
* Matching is textual and line oriented. Vendor-specific indentation and
  multi-line objects (for example some banner or certificate blocks) should be
  checked before writing custom patterns.
* A passing check proves that the expected lines are present in the stored
  export, not that the device is running the configuration. Confirm the last
  snapshot came from a successful, recent collection.
* Example configurations under `examples/` are lab data only, using RFC 5737
  documentation ranges and `.example` DNS names.

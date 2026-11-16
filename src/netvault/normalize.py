"""Configuration normalization and content hashing.

Normalization makes snapshots deterministic and comparable: line endings are
unified to ``\\n``, trailing whitespace is removed, runs of blank lines are
collapsed and volatile header lines (configuration change timestamps, NVRAM
update markers, derived NTP clock periods) are dropped before hashing. Leading
indentation is preserved because it carries meaning in nested vendor
configuration blocks.
"""

from __future__ import annotations

import hashlib
import re

_CRLF = re.compile(r"\r\n?")

# Lines that change without any semantic configuration change. They are
# excluded from the stored, hashed and diffed representation so that two
# identical device states produce the same digest.
_VOLATILE_LINE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^!\s*Last configuration change\b.*$"),
    re.compile(r"^!\s*NVRAM config last updated\b.*$"),
    re.compile(r"^!\s*No configuration change since last restart\b.*$"),
    re.compile(r"^!\s*Time:\s.*$"),
    re.compile(r"^Building configuration\.\.\.$"),
    re.compile(r"^Current configuration\s*:\s*\d+\s+bytes$"),
    re.compile(r"^Running configuration\s*:?\s*$"),
    re.compile(r"^;\s*Created on\b.*$"),
    re.compile(r"^;.*;\s*Created on\b.*$"),
    re.compile(r"^;\s*Ver #.*$"),
    re.compile(r"^ntp clock-period\s+\d+\s*$"),
)

_MAX_CONSECUTIVE_BLANK_LINES = 1


def normalize_config(text: str) -> str:
    """Return the canonical representation of a configuration export.

    The result always uses ``\\n`` line endings and ends with a single newline
    when non-empty. Normalizing an already normalized string is a no-op.
    """
    if not text or not text.strip():
        return ""
    unified = _CRLF.sub("\n", text)
    lines: list[str] = []
    blank_run = 0
    for raw_line in unified.split("\n"):
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped and any(pattern.match(stripped) for pattern in _VOLATILE_LINE_PATTERNS):
            continue
        if not stripped:
            blank_run += 1
            if blank_run > _MAX_CONSECUTIVE_BLANK_LINES:
                continue
        else:
            blank_run = 0
        lines.append(line)
    while lines and not lines[0]:
        del lines[0]
    while lines and not lines[-1]:
        del lines[-1]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def digest_normalized(normalized: str) -> str:
    """Return the SHA-256 hex digest of already normalized *normalized* text."""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def content_digest(text: str) -> str:
    """Return the SHA-256 hex digest of the normalized form of *text*."""
    return digest_normalized(normalize_config(text))

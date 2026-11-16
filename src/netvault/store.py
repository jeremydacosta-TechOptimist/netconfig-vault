"""Content-addressed snapshot vault: SQLite index plus SHA-256 blob objects.

Vault layout::

    <vault>/
    ├── vault.db                      SQLite index (devices, snapshots, blobs)
    └── objects/<2 hex>/<sha256>      normalized configuration blobs

Snapshots are append-only: the public API adds revisions but never rewrites
history. Identical content is stored once (blob deduplication); when a
collection produces content identical to the device's latest revision the
snapshot is reported as unchanged instead of creating a duplicate revision.
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import (
    DeviceInfo,
    DeviceSummary,
    SnapshotOutcome,
    SnapshotRecord,
    VaultStats,
)
from .normalize import digest_normalized, normalize_config

SCHEMA_VERSION = 1

_DB_FILE = "vault.db"
_OBJECTS_DIR = "objects"
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    vendor TEXT NOT NULL,
    site TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blobs (
    digest TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    line_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    digest TEXT NOT NULL REFERENCES blobs(digest),
    captured_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    source_name TEXT NOT NULL DEFAULT '',
    UNIQUE (device_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_device_revision
    ON snapshots(device_id, revision);
"""

_SELECT_SNAPSHOT = """
SELECT s.revision AS revision,
       s.digest AS digest,
       s.captured_at AS captured_at,
       s.note AS note,
       s.source_name AS source_name,
       b.size_bytes AS size_bytes,
       b.line_count AS line_count,
       d.name AS device,
       d.vendor AS vendor
FROM snapshots AS s
JOIN devices AS d ON d.id = s.device_id
JOIN blobs AS b ON b.digest = s.digest
"""


class VaultError(RuntimeError):
    """Base class for vault runtime failures."""


class NotInitializedError(VaultError):
    """Raised when a vault directory has not been initialized."""


class UnknownDeviceError(VaultError):
    """Raised when a device is not present in the vault index."""


class UnknownRevisionError(VaultError):
    """Raised when a requested revision does not exist for a device."""


def utc_now_iso() -> str:
    """Return the current UTC time as ``YYYY-MM-DDTHH:MM:SSZ``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record_from_row(row: sqlite3.Row) -> SnapshotRecord:
    """Build a :class:`SnapshotRecord` from a snapshot join row."""
    return SnapshotRecord(
        device=row["device"],
        vendor=row["vendor"],
        revision=int(row["revision"]),
        digest=row["digest"],
        captured_at=row["captured_at"],
        note=row["note"],
        source_name=row["source_name"],
        size_bytes=int(row["size_bytes"]),
        line_count=int(row["line_count"]),
    )


class Vault:
    """A configuration vault rooted at a directory.

    Use :meth:`initialize` to create a new vault and :meth:`open` to access an
    existing one. All read/write helpers open short-lived SQLite connections so
    the object is safe to reuse across CLI operations.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.display_path = os.fspath(root)
        self.db_path = self.root / _DB_FILE
        self.objects_dir = self.root / _OBJECTS_DIR

    @classmethod
    def initialize(cls, root: str | Path) -> "Vault":
        """Create the vault directory, index and blob store (idempotent)."""
        vault = cls(root)
        if vault.root.exists() and not vault.root.is_dir():
            raise VaultError(f"vault path is not a directory: {vault.display_path}")
        vault.root.mkdir(parents=True, exist_ok=True)
        vault.objects_dir.mkdir(parents=True, exist_ok=True)
        with vault._connect() as connection:
            try:
                connection.executescript(_SCHEMA)
            except sqlite3.DatabaseError as exc:
                raise VaultError(
                    f"cannot initialize vault at {vault.display_path!r}: {exc}"
                ) from exc
            row = connection.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            elif int(row["value"]) > SCHEMA_VERSION:
                raise VaultError(
                    f"vault schema version {row['value']} is newer than this netvault "
                    f"release (supported: {SCHEMA_VERSION})"
                )
        return vault

    @classmethod
    def open(cls, root: str | Path) -> "Vault":
        """Open an existing vault, validating that it was initialized."""
        vault = cls(root)
        if not vault.db_path.is_file():
            raise NotInitializedError(
                f"no vault found at {vault.display_path!r}; run 'netvault init' first"
            )
        try:
            with vault._connect() as connection:
                row = connection.execute(
                    "SELECT value FROM meta WHERE key = 'schema_version'"
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise NotInitializedError(
                f"{vault.display_path!r} does not look like a netvault vault"
            ) from exc
        if row is None:
            raise NotInitializedError(
                f"{vault.display_path!r} does not look like a netvault vault"
            )
        if int(row["value"]) > SCHEMA_VERSION:
            raise VaultError(
                f"vault schema version {row['value']} is newer than this netvault "
                f"release (supported: {SCHEMA_VERSION})"
            )
        return vault

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a SQLite connection with foreign keys enabled."""
        connection = sqlite3.connect(self.db_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _write_object(self, digest: str, normalized: str) -> None:
        """Store the normalized blob on disk, atomically and idempotently."""
        target = self.objects_dir / digest[:2] / digest
        if target.is_file():
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".tmp-")
        try:
            with os.fdopen(file_descriptor, "wb") as handle:
                handle.write(normalized.encode("utf-8"))
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def _ensure_device(
        self, connection: sqlite3.Connection, info: DeviceInfo, timestamp: str
    ) -> int:
        """Insert or refresh the device row and return its database id."""
        row = connection.execute(
            "SELECT id, site, role FROM devices WHERE name = ?", (info.name,)
        ).fetchone()
        if row is None:
            cursor = connection.execute(
                """
                INSERT INTO devices (name, vendor, site, role, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (info.name, info.vendor, info.site, info.role, timestamp, timestamp),
            )
            return int(cursor.lastrowid)
        device_id = int(row["id"])
        site = info.site or row["site"]
        role = info.role or row["role"]
        connection.execute(
            "UPDATE devices SET vendor = ?, site = ?, role = ?, last_seen = ? WHERE id = ?",
            (info.vendor, site, role, timestamp, device_id),
        )
        return device_id

    def _ensure_blob(
        self,
        connection: sqlite3.Connection,
        digest: str,
        normalized: str,
        timestamp: str,
    ) -> None:
        """Register the blob in the index if this content is new."""
        connection.execute(
            """
            INSERT OR IGNORE INTO blobs (digest, size_bytes, line_count, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                digest,
                len(normalized.encode("utf-8")),
                len(normalized.splitlines()),
                timestamp,
            ),
        )

    def snapshot(
        self,
        info: DeviceInfo,
        content: str,
        *,
        captured_at: str | None = None,
        note: str = "",
        source_name: str = "",
        dedupe: bool = True,
    ) -> SnapshotOutcome:
        """Store one configuration snapshot for *info*.

        Identical normalized content is hashed once and stored once. When
        *dedupe* is true and the content matches the device's latest revision,
        the existing revision is returned with ``created=False`` and no new
        revision is appended.

        Raises:
            VaultError: when the content is empty or *captured_at* is malformed.
        """
        normalized = normalize_config(content)
        if not normalized:
            raise VaultError("cannot store an empty configuration")
        digest = digest_normalized(normalized)
        timestamp = captured_at or utc_now_iso()
        if not _TIMESTAMP_PATTERN.match(timestamp):
            raise VaultError(
                f"invalid captured_at timestamp {timestamp!r}; "
                "expected UTC ISO-8601 such as 2026-01-31T09:30:00Z"
            )
        note = note.strip()

        self._write_object(digest, normalized)
        with self._connect() as connection:
            device_id = self._ensure_device(connection, info, timestamp)
            self._ensure_blob(connection, digest, normalized, timestamp)
            if dedupe:
                latest = connection.execute(
                    _SELECT_SNAPSHOT + " WHERE s.device_id = ? ORDER BY s.revision DESC LIMIT 1",
                    (device_id,),
                ).fetchone()
                if latest is not None and latest["digest"] == digest:
                    return SnapshotOutcome(record=_record_from_row(latest), created=False)
            revision = connection.execute(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM snapshots WHERE device_id = ?",
                (device_id,),
            ).fetchone()[0]
            cursor = connection.execute(
                """
                INSERT INTO snapshots
                    (device_id, revision, digest, captured_at, note, source_name)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (device_id, revision, digest, timestamp, note, source_name),
            )
            row = connection.execute(
                _SELECT_SNAPSHOT + " WHERE s.id = ?", (cursor.lastrowid,)
            ).fetchone()
        if row is None:  # pragma: no cover - defensive, the insert above guarantees a row
            raise VaultError("snapshot was written but could not be read back")
        return SnapshotOutcome(record=_record_from_row(row), created=True)

    def _require_device(self, connection: sqlite3.Connection, device: str) -> sqlite3.Row:
        """Return the device row or raise :class:`UnknownDeviceError`."""
        row = connection.execute(
            "SELECT id, name, vendor, site, role FROM devices WHERE name = ?", (device,)
        ).fetchone()
        if row is None:
            raise UnknownDeviceError(f"unknown device: {device}")
        return row

    def latest_snapshot(self, device: str) -> SnapshotRecord:
        """Return the newest revision of *device*."""
        with self._connect() as connection:
            device_row = self._require_device(connection, device)
            row = connection.execute(
                _SELECT_SNAPSHOT + " WHERE s.device_id = ? ORDER BY s.revision DESC LIMIT 1",
                (int(device_row["id"]),),
            ).fetchone()
        if row is None:
            raise VaultError(f"device {device!r} has no snapshots")
        return _record_from_row(row)

    def history(self, device: str) -> list[SnapshotRecord]:
        """Return all revisions of *device* in ascending revision order."""
        with self._connect() as connection:
            device_row = self._require_device(connection, device)
            rows = connection.execute(
                _SELECT_SNAPSHOT + " WHERE s.device_id = ? ORDER BY s.revision ASC",
                (int(device_row["id"]),),
            ).fetchall()
        return [_record_from_row(row) for row in rows]

    def get_snapshot(self, device: str, revision: int) -> SnapshotRecord:
        """Return one revision of *device*.

        Raises:
            UnknownDeviceError: when the device is not indexed.
            UnknownRevisionError: when the revision does not exist.
        """
        with self._connect() as connection:
            device_row = self._require_device(connection, device)
            row = connection.execute(
                _SELECT_SNAPSHOT + " WHERE s.device_id = ? AND s.revision = ?",
                (int(device_row["id"]), int(revision)),
            ).fetchone()
        if row is None:
            raise UnknownRevisionError(
                f"device {device!r} has no revision {revision}"
            )
        return _record_from_row(row)

    def read_content(self, digest: str) -> str:
        """Return the normalized configuration stored for *digest*."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT digest FROM blobs WHERE digest = ?", (digest,)
            ).fetchone()
        if row is None:
            raise VaultError(f"blob {digest!r} is not indexed in this vault")
        path = self.objects_dir / digest[:2] / digest
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise VaultError(f"blob file missing for {digest!r}: {exc}") from exc

    def read_revision(self, device: str, revision: int) -> tuple[SnapshotRecord, str]:
        """Return the record and configuration text of one revision."""
        record = self.get_snapshot(device, revision)
        return record, self.read_content(record.digest)

    def list_devices(self) -> list[DeviceSummary]:
        """Return all indexed devices with revision counters, sorted by name."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT d.name AS name,
                       d.vendor AS vendor,
                       d.site AS site,
                       d.role AS role,
                       COUNT(s.id) AS revisions,
                       COALESCE(latest.revision, 0) AS latest_revision,
                       COALESCE(latest.captured_at, '') AS latest_captured_at,
                       COALESCE(latest.digest, '') AS latest_digest
                FROM devices AS d
                LEFT JOIN snapshots AS s ON s.device_id = d.id
                LEFT JOIN snapshots AS latest
                       ON latest.device_id = d.id
                      AND latest.revision = (
                          SELECT MAX(inner.revision)
                          FROM snapshots AS inner
                          WHERE inner.device_id = d.id
                      )
                GROUP BY d.id
                ORDER BY d.name COLLATE NOCASE ASC
                """
            ).fetchall()
        return [
            DeviceSummary(
                name=row["name"],
                vendor=row["vendor"],
                site=row["site"],
                role=row["role"],
                revisions=int(row["revisions"]),
                latest_revision=int(row["latest_revision"]),
                latest_captured_at=row["latest_captured_at"],
                latest_digest=row["latest_digest"],
            )
            for row in rows
        ]

    def stats(self) -> VaultStats:
        """Return counters for devices, snapshots, blobs and stored bytes."""
        with self._connect() as connection:
            devices = int(connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0])
            snapshots = int(connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0])
            blob_row = connection.execute(
                "SELECT COUNT(*) AS blobs, COALESCE(SUM(size_bytes), 0) AS bytes FROM blobs"
            ).fetchone()
        return VaultStats(
            devices=devices,
            snapshots=snapshots,
            blobs=int(blob_row["blobs"]),
            config_bytes=int(blob_row["bytes"]),
        )

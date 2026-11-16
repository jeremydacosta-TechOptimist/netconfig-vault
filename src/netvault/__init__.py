"""netvault - offline network configuration vault, versioning and compliance.

The package stores device configuration snapshots in a content-addressed,
SQLite-backed vault, computes configuration differences between revisions and
evaluates declarative compliance baselines against the latest configuration.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]

"""Optional per-project configuration.

Looks for ``.trivyignore-cli.toml`` in the repo root, or a ``[tool.trivyignore]``
table inside ``pyproject.toml``. Every key mirrors a CLI flag; explicit flags
always win over config values.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

CONFIG_NAMES = (".trivyignore-cli.toml", "trivyignore-cli.toml")

KNOWN_KEYS = {
    "files",
    "images",
    "context",
    "severity",
    "ignore_file",
    "format",
    "scanners",
    "ignore_unfixed",
    "patterns",
    "exclude",
    "no_gitignore",
    "comment",
    "keep_images",
    "pull",
    "no_cache",
    "timeout",
    "trivy_args",
}


def load_config(root: Path, explicit: Path | None = None) -> dict[str, Any]:
    """Return the config table, or an empty dict when none exists."""
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"config file not found: {explicit}")
        return _validate(_read_toml(explicit), explicit)

    for name in CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            return _validate(_read_toml(candidate), candidate)

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _read_toml(pyproject)
        table = (data.get("tool") or {}).get("trivyignore")
        if isinstance(table, dict):
            return _validate(table, pyproject)

    return {}


def _read_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _validate(table: dict[str, Any], source: Path) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in table.items():
        norm = key.replace("-", "_")
        if norm not in KNOWN_KEYS:
            raise ValueError(f"{source}: unknown config key {key!r}")
        normalized[norm] = value
    normalized["_source"] = source
    return normalized

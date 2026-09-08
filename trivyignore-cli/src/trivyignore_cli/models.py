"""Core data types shared across the package."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Trivy severity ordering, weakest first.
SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Maps a Trivy JSON result key onto the .trivyignore.yaml section it belongs to.
SECTION_FOR_KIND = {
    "vulnerabilities": "vulnerabilities",
    "misconfigurations": "misconfigurations",
    "secrets": "secrets",
    "licenses": "licenses",
}

_TAG_SAFE = re.compile(r"[^a-z0-9._-]+")


@dataclass(frozen=True)
class Finding:
    """A single scanner result that may be written into the ignore file."""

    id: str
    severity: str
    kind: str = "vulnerabilities"
    title: str = ""
    pkg_name: str = ""

    @property
    def section(self) -> str:
        return SECTION_FOR_KIND.get(self.kind, "vulnerabilities")


@dataclass
class Target:
    """A build/scan unit: either a Dockerfile to build, or a prebuilt image."""

    dockerfile: Path | None = None
    context: Path | None = None
    image: str | None = None
    name: str = ""
    build_args: dict[str, str] = field(default_factory=dict)
    target_stage: str | None = None
    platform: str | None = None

    def __post_init__(self) -> None:
        if self.dockerfile is None and self.image is None:
            raise ValueError("Target needs either a dockerfile or an image")
        if not self.name:
            self.name = self.image or str(self.dockerfile)

    @property
    def is_prebuilt(self) -> bool:
        return self.dockerfile is None

    def tag_for(self, root: Path) -> str:
        """Deterministic local tag so Trivy can pull the image from the daemon.

        Trivy rejects a bare 64-char image hash as an invalid repository name,
        so every built image is scanned by tag instead.
        """
        if self.image:
            return self.image
        assert self.dockerfile is not None
        try:
            rel = self.dockerfile.resolve().relative_to(root.resolve())
        except ValueError:
            rel = Path(self.dockerfile.name)
        slug = _TAG_SAFE.sub("-", str(rel).lower().replace("/", "-")).strip("-")
        return f"trivyscan/{slug or 'image'}:latest"


def normalize_severities(raw: str | list[str]) -> list[str]:
    """Turn 'high,critical' or ['HIGH'] into a validated uppercase list."""
    if isinstance(raw, str):
        parts = [p for p in re.split(r"[,\s]+", raw) if p]
    else:
        parts = [str(p).strip() for p in raw if str(p).strip()]

    out: list[str] = []
    for part in parts:
        upper = part.upper()
        if upper == "ALL":
            return list(SEVERITY_ORDER)
        if upper not in SEVERITY_ORDER:
            raise ValueError(
                f"unknown severity {part!r}; expected one of "
                f"{', '.join(SEVERITY_ORDER)} or ALL"
            )
        if upper not in out:
            out.append(upper)
    if not out:
        raise ValueError("no severities given")
    return sorted(out, key=SEVERITY_ORDER.index)

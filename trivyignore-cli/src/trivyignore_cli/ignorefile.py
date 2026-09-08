"""Read, merge and write Trivy ignore files.

Two formats are supported:

``yaml``
    The modern ``.trivyignore.yaml`` layout, with top level ``vulnerabilities``,
    ``misconfigurations``, ``secrets`` and ``licenses`` sections.

``plain``
    The legacy ``.trivyignore`` layout: one ID per line.

Merging is line based rather than via a YAML round trip. That keeps existing
comments, ordering, ``statement``/``expired_at`` fields and hand written notes
byte-for-byte intact; new entries are appended to the end of their section.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import SECTION_FOR_KIND, Finding

SECTION_NAMES = list(dict.fromkeys(SECTION_FOR_KIND.values()))

_SECTION_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(?:#.*)?$")
_ENTRY_ID_RE = re.compile(
    r"^[ \t]*-[ \t]+(?:id|ID)[ \t]*:[ \t]*[\"']?([A-Za-z0-9][A-Za-z0-9._-]*)[\"']?"
)
# A bare `- CVE-2021-1234` entry, which Trivy also accepts.
_ENTRY_BARE_RE = re.compile(
    r"^[ \t]*-[ \t]+[\"']?([A-Za-z0-9][A-Za-z0-9._-]*)[\"']?[ \t]*(?:#.*)?$"
)
_PLAIN_ID_RE = re.compile(r"^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*(?:#.*)?$")

DEFAULT_INDENT = "  "


def detect_format(path: Path) -> str:
    """Pick a format from the filename, falling back to yaml."""
    name = path.name.lower()
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    if name == ".trivyignore" or name.endswith(".trivyignore"):
        return "plain"
    return "yaml"


@dataclass
class _Section:
    name: str
    header_index: int
    end_index: int  # exclusive; index of the line after the section's last entry
    indent: str = DEFAULT_INDENT


@dataclass
class IgnoreFile:
    """An ignore file loaded into memory, ready to accept new findings."""

    path: Path
    format: str = "yaml"
    lines: list[str] = field(default_factory=list)
    sections: dict[str, _Section] = field(default_factory=dict)
    ids: dict[str, set[str]] = field(default_factory=dict)
    added: list[Finding] = field(default_factory=list)

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(cls, path: Path, fmt: str | None = None) -> IgnoreFile:
        fmt = fmt or detect_format(path)
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        lines = text.splitlines()
        obj = cls(path=path, format=fmt, lines=lines)
        obj._parse()
        return obj

    def _parse(self) -> None:
        self.sections = {}
        self.ids = {name: set() for name in SECTION_NAMES}

        if self.format == "plain":
            found = set()
            for line in self.lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = _PLAIN_ID_RE.match(line)
                if m:
                    found.add(m.group(1))
            self.ids["vulnerabilities"] = found
            return

        current: _Section | None = None
        for index, line in enumerate(self.lines):
            if not line.strip():
                continue

            header = _SECTION_RE.match(line)
            if header:
                name = header.group(1)
                current = _Section(name=name, header_index=index, end_index=index + 1)
                self.sections[name] = current
                self.ids.setdefault(name, set())
                continue

            if current is None:
                continue

            # Any indented line still belongs to the section that opened above.
            if line.startswith((" ", "\t", "-")):
                current.end_index = index + 1
                m = _ENTRY_ID_RE.match(line) or _ENTRY_BARE_RE.match(line)
                if m:
                    self.ids[current.name].add(m.group(1))
                    indent = line[: len(line) - len(line.lstrip(" \t"))]
                    current.indent = indent or DEFAULT_INDENT
            else:
                current = None

    # -- querying --------------------------------------------------------

    def has(self, finding: Finding) -> bool:
        return finding.id in self.ids.get(finding.section, set())

    def all_ids(self) -> set[str]:
        return {i for group in self.ids.values() for i in group}

    # -- mutation --------------------------------------------------------

    def add(self, finding: Finding, comment: bool = True) -> bool:
        """Record a finding. Returns False when it was already present."""
        if self.has(finding):
            return False
        self.ids.setdefault(finding.section, set()).add(finding.id)
        self.added.append(finding)

        if self.format == "plain":
            entry = f"{finding.id} # {finding.severity}" if comment else finding.id
            self.lines.append(entry)
            return True

        section = self.sections.get(finding.section)
        entry = f"{DEFAULT_INDENT}- id: {finding.id}"
        if section is None:
            if self.lines:
                self.lines.append("")
            self.lines.append(f"{finding.section}:")
            section = _Section(
                name=finding.section,
                header_index=len(self.lines) - 1,
                end_index=len(self.lines),
            )
            self.sections[finding.section] = section
        else:
            entry = f"{section.indent}- id: {finding.id}"

        if comment and finding.severity:
            entry = f"{entry} # {finding.severity}"

        self.lines.insert(section.end_index, entry)
        self._shift_after(section, section.end_index)
        return True

    def _shift_after(self, inserted_in: _Section, at: int) -> None:
        """Keep section bounds correct after inserting one line at ``at``."""
        for section in self.sections.values():
            if section.header_index >= at:
                section.header_index += 1
            if section.end_index >= at or section is inserted_in:
                section.end_index += 1

    # -- serialising -----------------------------------------------------

    def render(self) -> str:
        body = "\n".join(self.lines)
        if body and not body.endswith("\n"):
            body += "\n"
        return body

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(self.render(), encoding="utf-8")
        tmp.replace(self.path)

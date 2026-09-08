"""Locate Dockerfiles in a repository and turn CLI specs into targets."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from .models import Target

DEFAULT_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile")

# Directories that never contain a Dockerfile worth scanning.
PRUNE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    "dist",
    "build",
    ".tox",
}

# Dockerfile-ish names that are usually test fixtures or examples.
DEFAULT_EXCLUDES = ("**/testdata/**", "**/fixtures/**", "**/examples/**")


def repo_root(start: Path) -> Path:
    """Nearest git root, or ``start`` when not inside a repository."""
    try:
        out = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return start.resolve()


def _matches(name: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def _excluded(rel: Path, excludes: tuple[str, ...] | list[str]) -> bool:
    text = rel.as_posix()
    for pat in excludes:
        if fnmatch.fnmatch(text, pat) or fnmatch.fnmatch(text, pat.lstrip("*/")):
            return True
        if pat.startswith("**/") and fnmatch.fnmatch(text, pat[3:]):
            return True
    return False


def _git_ignored(root: Path, paths: list[Path]) -> set[Path]:
    """Ask git which of ``paths`` are ignored. Empty set when git is absent."""
    if not paths:
        return set()
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--stdin"],
            input="\n".join(str(p) for p in paths),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return set()
    if proc.returncode not in (0, 1):
        return set()
    return {Path(line) for line in proc.stdout.splitlines() if line.strip()}


def find_dockerfiles(
    root: Path,
    patterns: tuple[str, ...] | list[str] = DEFAULT_PATTERNS,
    excludes: tuple[str, ...] | list[str] = DEFAULT_EXCLUDES,
    respect_gitignore: bool = True,
) -> list[Path]:
    """Walk ``root`` and return every matching Dockerfile, sorted by path."""
    root = root.resolve()
    hits: list[Path] = []

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in sorted(entries):
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in PRUNE_DIRS:
                    continue
                stack.append(entry)
                continue
            if not entry.is_file():
                continue
            if not _matches(entry.name, patterns):
                continue
            # A .dockerignore sits next to Dockerfiles but is not one.
            if entry.name.startswith("."):
                continue
            rel = entry.relative_to(root)
            if _excluded(rel, excludes):
                continue
            hits.append(entry)

    if respect_gitignore and hits:
        ignored = _git_ignored(root, hits)
        if ignored:
            resolved = {p.resolve() for p in ignored}
            hits = [h for h in hits if h.resolve() not in resolved]

    return sorted(hits)


def parse_file_spec(spec: str, root: Path, default_context: Path | None = None) -> Target:
    """Parse ``path/Dockerfile`` or ``path/Dockerfile:build/context``.

    Windows drive letters (``C:\\x``) are handled by only splitting on a colon
    that is followed by a path separator or a non-drive-looking segment.
    """
    dockerfile_part, context_part = _split_spec(spec)

    dockerfile = Path(dockerfile_part)
    if not dockerfile.is_absolute():
        dockerfile = root / dockerfile

    if context_part:
        context = Path(context_part)
        if not context.is_absolute():
            context = root / context
    elif default_context is not None:
        context = default_context
    else:
        context = dockerfile.parent

    return Target(dockerfile=dockerfile, context=context)


def _split_spec(spec: str) -> tuple[str, str | None]:
    if ":" not in spec:
        return spec, None
    head, _, tail = spec.rpartition(":")
    if not head:
        return spec, None
    # 'C:/path/Dockerfile' -> not a context separator.
    if len(head) == 1 and head.isalpha():
        return spec, None
    if not tail:
        return head, None
    return head, tail


def build_targets(
    root: Path,
    file_specs: list[str] | None = None,
    images: list[str] | None = None,
    context_override: Path | None = None,
    patterns: tuple[str, ...] | list[str] = DEFAULT_PATTERNS,
    excludes: tuple[str, ...] | list[str] = DEFAULT_EXCLUDES,
    respect_gitignore: bool = True,
) -> list[Target]:
    """Resolve explicit specs, or fall back to auto-discovery."""
    targets: list[Target] = []

    for image in images or []:
        targets.append(Target(image=image))

    if file_specs:
        for spec in file_specs:
            targets.append(parse_file_spec(spec, root, context_override))
        return targets

    if targets:
        # Only prebuilt images were requested; do not also walk the tree.
        return targets

    for path in find_dockerfiles(root, patterns, excludes, respect_gitignore):
        context = context_override or path.parent
        targets.append(Target(dockerfile=path, context=context))
    return targets

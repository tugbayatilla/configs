"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .discovery import DEFAULT_EXCLUDES, DEFAULT_PATTERNS, build_targets, repo_root
from .ignorefile import IgnoreFile, detect_format
from .models import Target, normalize_severities
from .runner import ToolError, build_image, image_id, remove_image, scan_image

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ADDED = 2  # only with --check


def _color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class Printer:
    def __init__(self, quiet: bool = False, stream=sys.stderr) -> None:
        self.quiet = quiet
        self.stream = stream
        self.tty = _color(stream)

    def _emit(self, text: str) -> None:
        print(text, file=self.stream, flush=True)

    def step(self, text: str) -> None:
        if self.quiet:
            return
        self._emit(f"==> {text}" if not self.tty else f"\033[1;34m==>\033[0m {text}")

    def info(self, text: str) -> None:
        if self.quiet:
            return
        self._emit(f"    {text}")

    def warn(self, text: str) -> None:
        self._emit(f"WARN: {text}" if not self.tty else f"\033[1;33mWARN:\033[0m {text}")

    def error(self, text: str) -> None:
        self._emit(f"ERROR: {text}" if not self.tty else f"\033[1;31mERROR:\033[0m {text}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trivyignore",
        description=(
            "Build Docker images, scan them with Trivy, and append new findings "
            "to a Trivy ignore file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  trivyignore                       # discover Dockerfiles, sync HIGH findings\n"
            "  trivyignore -f deploy/api/Dockerfile -f deploy/db/Dockerfile\n"
            "  trivyignore -f svc/Dockerfile:.   # build with the repo root as context\n"
            "  trivyignore --image nginx:latest --severity HIGH,CRITICAL\n"
            "  trivyignore --list                # show what would be scanned\n"
            "  trivyignore --check               # fail if new findings appear (CI)\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    src = parser.add_argument_group("targets")
    src.add_argument(
        "-f",
        "--file",
        dest="files",
        action="append",
        metavar="DOCKERFILE[:CONTEXT]",
        help="Dockerfile to build; repeatable. Disables auto-discovery.",
    )
    src.add_argument(
        "--image",
        dest="images",
        action="append",
        metavar="IMAGE",
        help="Scan an existing image instead of building; repeatable.",
    )
    src.add_argument(
        "-C",
        "--context",
        metavar="DIR",
        help="Build context for all targets (default: the Dockerfile's directory).",
    )
    src.add_argument(
        "--root",
        metavar="DIR",
        help="Repository root (default: git top level, else the cwd).",
    )
    src.add_argument(
        "--pattern",
        dest="patterns",
        action="append",
        metavar="GLOB",
        help=f"Filename glob for discovery; repeatable (default: {', '.join(DEFAULT_PATTERNS)}).",
    )
    src.add_argument(
        "--exclude",
        dest="exclude",
        action="append",
        metavar="GLOB",
        help="Path glob to skip during discovery; repeatable.",
    )
    src.add_argument(
        "--no-gitignore",
        action="store_true",
        help="Do not skip Dockerfiles that git ignores.",
    )

    scan = parser.add_argument_group("scanning")
    scan.add_argument(
        "-s",
        "--severity",
        default=None,
        metavar="LEVELS",
        help="Comma separated severities, or ALL (default: HIGH).",
    )
    scan.add_argument(
        "--scanners",
        metavar="LIST",
        help="Trivy scanners, e.g. vuln,secret,misconfig (default: trivy's own).",
    )
    scan.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="Only record findings that have a fix available.",
    )
    scan.add_argument("--timeout", metavar="DURATION", help="Trivy timeout, e.g. 10m.")
    scan.add_argument(
        "--trivy-arg",
        dest="trivy_args",
        action="append",
        metavar="ARG",
        help="Extra argument passed through to trivy; repeatable.",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "-o",
        "--ignore-file",
        metavar="PATH",
        help="Ignore file to update (default: <root>/.trivyignore.yaml).",
    )
    out.add_argument(
        "--format",
        choices=("yaml", "plain", "auto"),
        default="auto",
        help="Ignore file format (default: inferred from the filename).",
    )
    out.add_argument(
        "--no-comment",
        action="store_true",
        help="Do not append '# SEVERITY' comments to new entries.",
    )
    out.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Show what would be added without writing the file.",
    )
    out.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 2 when new findings exist. Implies --dry-run.",
    )
    out.add_argument(
        "--list",
        dest="list_only",
        action="store_true",
        help="List resolved targets and exit without building.",
    )

    misc = parser.add_argument_group("misc")
    misc.add_argument("--config", metavar="PATH", help="Config file to load.")
    misc.add_argument("--no-config", action="store_true", help="Ignore any config file.")
    misc.add_argument("--pull", action="store_true", help="Pass --pull to docker build.")
    misc.add_argument("--no-cache", action="store_true", help="Pass --no-cache to docker build.")
    misc.add_argument(
        "--keep-images",
        action="store_true",
        help="Keep the temporary trivyscan/* images after scanning.",
    )
    misc.add_argument(
        "--build-output",
        action="store_true",
        help="Stream docker build output instead of hiding it.",
    )
    misc.add_argument("-q", "--quiet", action="store_true", help="Only report errors.")
    misc.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue after a target fails; exit non-zero at the end.",
    )
    return parser


def _resolve(args: argparse.Namespace, cfg: dict) -> None:
    """Fill unset CLI args from the config table."""

    def pick(name: str, cfg_key: str | None = None, default=None):
        current = getattr(args, name, None)
        if current not in (None, False, [], "auto"):
            return current
        value = cfg.get(cfg_key or name)
        if value is None:
            return current if current is not None else default
        return value

    args.files = pick("files", "files") or []
    args.images = pick("images", "images") or []
    args.patterns = pick("patterns", "patterns") or list(DEFAULT_PATTERNS)
    args.exclude = pick("exclude", "exclude") or list(DEFAULT_EXCLUDES)
    args.trivy_args = pick("trivy_args", "trivy_args") or []
    args.severity = pick("severity", "severity") or "HIGH"
    args.context = pick("context", "context")
    args.ignore_file = pick("ignore_file", "ignore_file")
    args.scanners = pick("scanners", "scanners")
    args.timeout = pick("timeout", "timeout")
    args.ignore_unfixed = bool(pick("ignore_unfixed", "ignore_unfixed", False))
    args.no_gitignore = bool(pick("no_gitignore", "no_gitignore", False))
    args.keep_images = bool(pick("keep_images", "keep_images", False))
    args.pull = bool(pick("pull", "pull", False))
    args.no_cache = bool(pick("no_cache", "no_cache", False))
    if args.format == "auto" and cfg.get("format"):
        args.format = cfg["format"]
    if cfg.get("comment") is False:
        args.no_comment = True


def _describe(target: Target, root: Path) -> str:
    if target.is_prebuilt:
        return f"image {target.image}"
    assert target.dockerfile is not None
    try:
        rel = target.dockerfile.resolve().relative_to(root.resolve())
    except ValueError:
        rel = target.dockerfile
    ctx = target.context or target.dockerfile.parent
    try:
        ctx_rel = ctx.resolve().relative_to(root.resolve()) or Path(".")
    except ValueError:
        ctx_rel = ctx
    return f"{rel} (context: {ctx_rel})"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    printer = Printer(quiet=args.quiet)

    if args.check:
        args.dry_run = True

    start = Path(args.root).resolve() if args.root else Path.cwd()
    if not start.is_dir():
        printer.error(f"root is not a directory: {start}")
        return EXIT_ERROR
    root = start if args.root else repo_root(start)

    try:
        cfg = {} if args.no_config else load_config(
            root, Path(args.config).resolve() if args.config else None
        )
    except (OSError, ValueError) as exc:
        printer.error(str(exc))
        return EXIT_ERROR

    if cfg.get("_source") and not args.quiet:
        printer.info(f"config: {cfg['_source']}")
    _resolve(args, cfg)

    try:
        severities = normalize_severities(args.severity)
    except ValueError as exc:
        printer.error(str(exc))
        return EXIT_ERROR

    context_override = None
    if args.context:
        context_override = Path(args.context)
        if not context_override.is_absolute():
            context_override = root / context_override

    targets = build_targets(
        root=root,
        file_specs=args.files,
        images=args.images,
        context_override=context_override,
        patterns=args.patterns,
        excludes=args.exclude,
        respect_gitignore=not args.no_gitignore,
    )

    if not targets:
        printer.warn(f"no Dockerfiles found under {root}")
        return EXIT_OK

    if args.list_only:
        for target in targets:
            print(_describe(target, root))
        return EXIT_OK

    ignore_path = (
        Path(args.ignore_file)
        if args.ignore_file
        else root / ".trivyignore.yaml"
    )
    if not ignore_path.is_absolute():
        ignore_path = root / ignore_path
    fmt = args.format if args.format != "auto" else detect_format(ignore_path)

    try:
        ignore = IgnoreFile.load(ignore_path, fmt)
    except OSError as exc:
        printer.error(f"could not read {ignore_path}: {exc}")
        return EXIT_ERROR

    printer.step(
        f"{len(targets)} target(s), severity {','.join(severities)}, "
        f"ignore file {ignore_path}"
    )

    scanners = [s.strip() for s in args.scanners.split(",")] if args.scanners else None
    failures = 0
    seen_before = len(ignore.all_ids())

    for target in targets:
        label = _describe(target, root)
        try:
            if target.is_prebuilt:
                tag = target.image  # type: ignore[assignment]
                printer.step(f"Scanning {label}")
            else:
                printer.step(f"Building {label}")
                tag = build_image(
                    target,
                    root,
                    quiet=not args.build_output,
                    pull=args.pull,
                    no_cache=args.no_cache,
                )
                digest = image_id(tag)
                printer.info(f"tag: {tag}")
                if digest:
                    printer.info(f"image: {digest[:12]}")
                printer.step(f"Scanning {tag}")

            findings = scan_image(
                tag,
                severities,
                scanners=scanners,
                ignore_unfixed=args.ignore_unfixed,
                extra_args=args.trivy_args,
                timeout=args.timeout,
            )
        except ToolError as exc:
            failures += 1
            printer.error(str(exc))
            if args.keep_going:
                continue
            return EXIT_ERROR
        finally:
            if not target.is_prebuilt and not args.keep_images and not args.dry_run:
                remove_image(target.tag_for(root))

        added_here = 0
        for finding in findings:
            if ignore.add(finding, comment=not args.no_comment):
                added_here += 1
                printer.info(f"+ {finding.id} ({finding.severity})")

        if not findings:
            printer.info("no findings at the selected severity")
        elif added_here == 0:
            printer.info(f"{len(findings)} finding(s), all already ignored")
        else:
            printer.info(f"{added_here} new of {len(findings)} finding(s)")

    added = len(ignore.added)

    if args.check:
        if added:
            printer.error(f"{added} finding(s) not present in {ignore_path}")
            for finding in ignore.added:
                print(f"{finding.id} {finding.severity}")
            return EXIT_ADDED
        printer.step(f"Done. No new findings ({seen_before} already ignored).")
        return EXIT_ERROR if failures else EXIT_OK

    if args.dry_run:
        printer.step(f"Dry run. Would add {added} finding(s) to {ignore_path}")
        if added:
            print(ignore.render(), end="")
        return EXIT_ERROR if failures else EXIT_OK

    if added:
        try:
            ignore.save()
        except OSError as exc:
            printer.error(f"could not write {ignore_path}: {exc}")
            return EXIT_ERROR

    printer.step(f"Done. Added {added} new finding(s) to {ignore_path}")
    return EXIT_ERROR if failures else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

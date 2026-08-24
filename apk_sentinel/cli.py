"""Command-line interface: analyse an APK and write report files.

Usage::

    python -m apk_sentinel app.apk                 # writes reports/ next to cwd
    python -m apk_sentinel app.apk -o out --format all
    python -m apk_sentinel app.apk --format json   # machine-readable to stdout
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List

from . import __version__
from .analyzer import analyze_apk
from .models import Severity
from .report import render_html, render_json, render_markdown

_SEV_TTY = {
    Severity.CRITICAL: "\033[41;97m CRIT \033[0m",
    Severity.HIGH: "\033[31;1mHIGH\033[0m",
    Severity.MEDIUM: "\033[33;1mMED \033[0m",
    Severity.LOW: "\033[36mLOW \033[0m",
    Severity.INFO: "\033[90mINFO\033[0m",
}


def _color(enabled: bool, sev: Severity) -> str:
    if enabled:
        return _SEV_TTY[sev]
    return sev.value.upper()[:4]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apk-sentinel",
        description="Static security & quality analysis for Android APKs.",
    )
    p.add_argument("apk", help="path to the .apk file to analyse")
    p.add_argument("-o", "--output", default="reports",
                   help="output directory for report files (default: reports/)")
    p.add_argument("-f", "--format", default="all",
                   choices=["all", "html", "md", "json"],
                   help="report format(s) to write (default: all)")
    p.add_argument("--stdout", action="store_true",
                   help="print the chosen single format to stdout instead of writing files")
    p.add_argument("--no-deep", action="store_true",
                   help="skip DEX string extraction (faster, manifest-only)")
    p.add_argument("--fail-on", default=None,
                   choices=["critical", "high", "medium", "low"],
                   help="exit non-zero if a finding at/above this severity exists (CI gate)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour in the console summary")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress the console summary")
    p.add_argument("-V", "--version", action="version", version=f"APK Sentinel {__version__}")
    return p


def _force_utf8() -> None:
    # Windows consoles default to cp1252 and crash on non-ASCII output. Emit
    # UTF-8 (replacing anything unencodable) so the CLI never dies on a glyph.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv: List[str] | None = None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)

    if not os.path.isfile(args.apk):
        print(f"error: file not found: {args.apk}", file=sys.stderr)
        return 2

    try:
        result = analyze_apk(args.apk, deep=not args.no_deep)
    except Exception as exc:
        print(f"error: failed to analyse APK: {exc}", file=sys.stderr)
        return 2

    # -- stdout single-format mode --------------------------------------
    if args.stdout:
        fmt = args.format if args.format != "all" else "json"
        renderers = {"json": render_json, "md": render_markdown, "html": render_html}
        sys.stdout.write(renderers[fmt](result))
        return _exit_code(result, args.fail_on)

    # -- write files ----------------------------------------------------
    os.makedirs(args.output, exist_ok=True)
    stem = os.path.splitext(os.path.basename(args.apk))[0]
    written = []
    want = ["html", "md", "json"] if args.format == "all" else [args.format]
    renderers = {"json": render_json, "md": render_markdown, "html": render_html}
    ext = {"json": "json", "md": "md", "html": "html"}
    for fmt in want:
        path = os.path.join(args.output, f"{stem}.report.{ext[fmt]}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(renderers[fmt](result))
        written.append(path)

    if not args.quiet:
        _print_summary(result, args, written)

    return _exit_code(result, args.fail_on)


def _print_summary(result, args, written) -> None:
    use_color = (not args.no_color) and sys.stdout.isatty()
    m = result.manifest
    c = result.severity_counts
    print()
    print(f"  APK Sentinel {__version__}  |  {result.file_name}")
    print(f"  Package : {m.package or '?'}  v{m.version_name or '?'}")
    print(f"  Grade   : {result.grade}   Risk {result.risk_score}/100")
    print(f"  Findings: {c['critical']} critical | {c['high']} high | {c['medium']} medium | "
          f"{c['low']} low | {c['info']} info")
    print()
    for f in result.sorted_findings():
        if f.severity == Severity.INFO:
            continue
        print(f"    [{_color(use_color, f.severity)}] {f.title}")
    print()
    for pth in written:
        print(f"  -> {pth}")
    print()


def _exit_code(result, fail_on) -> int:
    if not fail_on:
        return 0
    threshold = Severity(fail_on).rank
    for f in result.findings:
        if f.severity.rank <= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

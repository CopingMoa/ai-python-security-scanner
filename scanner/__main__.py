"""Command-line entry point: python -m scanner PATH [PATH ...]"""

import argparse
import json
import sys
from pathlib import Path

from . import ai_review
from .rules import Finding, scan_source


def iter_python_files(paths: list[str]):
    for path in map(Path, paths):
        if path.is_dir():
            yield from sorted(path.rglob("*.py"))
        elif path.suffix == ".py":
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner", description="Scan Python source for common security issues.")
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--ai", action="store_true", help="add AI-assisted review (see scanner/ai_review.py)")
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    for path in iter_python_files(args.paths):
        source = path.read_text(encoding="utf-8")
        try:
            file_findings = scan_source(source, path.as_posix())
        except SyntaxError as exc:
            print(f"skipped {path}: {exc}", file=sys.stderr)
            continue
        if args.ai:
            file_findings += ai_review.review(source, path.as_posix(), file_findings)
        findings += file_findings

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.file}:{f.line}  {f.severity:<6}  {f.rule}  {f.message}")
        print(f"\n{len(findings)} finding(s)")

    # Non-zero exit lets CI pipelines fail on findings.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

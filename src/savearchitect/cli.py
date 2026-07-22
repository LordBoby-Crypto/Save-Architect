from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analysis import FileAnalyzer, analyze_many


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="savearchitect",
        description="Analyze game save files and produce metadata-only research manifests.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="One or more files or directories to analyze.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write the JSON report to this file instead of stdout.",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=1024 * 1024,
        help="Maximum bytes sampled per file for entropy and text analysis.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if len(args.paths) == 1:
            report = FileAnalyzer(sample_limit=args.sample_limit).analyze_path(args.paths[0])
        else:
            report = analyze_many(args.paths)
    except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        parser.exit(2, f"savearchitect: error: {exc}\n")

    payload = report.to_json() + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

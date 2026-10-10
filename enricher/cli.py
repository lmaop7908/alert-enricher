"""Command-line interface: python -m enricher <indicator> [...]"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

from . import report
from .cache import Cache
from .core import enrich
from .indicators import hash_file, human_size
from .localfile import LocalFile, inspect_file
from .providers import build_providers

FORMATS = {"text": report.as_text, "json": report.as_json, "html": report.as_html}


def load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env loader (no extra dependency). Real env vars win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def read_indicators(path: Path) -> list[str]:
    """Read indicators from a .txt (one per line) or .csv (first column)."""
    values: list[str] = []
    with path.open(newline="") as fh:
        if path.suffix.lower() == ".csv":
            for row in csv.reader(fh):
                if row and row[0].strip() and not row[0].startswith("#"):
                    values.append(row[0].strip())
        else:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    values.append(line)
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="enricher",
        description="Enrich IPs, domains, URLs, and file hashes with threat intel.",
    )
    parser.add_argument("indicators", nargs="*", help="indicators to look up")
    parser.add_argument("-f", "--file", type=Path, help="file of indicators (.txt or .csv)")
    parser.add_argument(
        "--hash-file",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help="hash a local file (SHA-256) and look up the hash; repeatable. "
        "The file itself is never uploaded.",
    )
    parser.add_argument("--format", choices=FORMATS, default="text")
    parser.add_argument("-o", "--output", type=Path, help="write report to this file")
    parser.add_argument("--no-cache", action="store_true", help="skip the local result cache")
    args = parser.parse_args(argv)

    load_dotenv()

    targets = list(args.indicators)
    if args.file:
        try:
            targets += read_indicators(args.file)
        except OSError as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
    labels: dict[str, str] = {}
    sources: dict[str, str] = {}
    local: dict[str, LocalFile] = {}
    for path in args.hash_file:
        try:
            digest = hash_file(path)
            size = path.stat().st_size
            local.setdefault(digest, inspect_file(path))
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        targets.append(digest)
        labels.setdefault(digest, path.name)
        sources.setdefault(digest, f"{path.resolve()} ({human_size(size)})")

    if not targets:
        parser.error("provide at least one indicator, --file, or --hash-file")

    providers = build_providers(dict(os.environ))
    if not any(p.api_key for p in providers):
        print(
            "error: no API keys found. Copy .env.example to .env and add at least one key.",
            file=sys.stderr,
        )
        return 2

    cache = None if args.no_cache else Cache(Path.home() / ".cache" / "alert-enricher" / "cache.json")
    results = [
        enrich(t, providers, cache, labels.get(t, ""), sources.get(t, ""), local.get(t))
        for t in dict.fromkeys(targets)
    ]
    if cache:
        cache.save()

    output = FORMATS[args.format](results)
    if args.output:
        args.output.write_text(output)
        print(f"wrote {args.output}")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())

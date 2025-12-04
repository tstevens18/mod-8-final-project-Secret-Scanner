
"""
secret_scanner.py

A simple CLI tool that scans files or directories for patterns that look like
hardcoded secrets (API keys, passwords, tokens, private keys, etc.).
"""

import argparse
import logging
import os
from pathlib import Path
import re
from typing import Dict, Iterable, List, Tuple



# Regex patterns for secrets

def build_patterns() -> List[Tuple[str, re.Pattern]]:
    """
    Build and return the list of (name, compiled_regex) patterns
    used to detect potential secrets.
    """
    patterns = [
        (
            "AWS Access Key ID",
            re.compile(r"AKIA[0-9A-Z]{16}")
        ),
        (
            "AWS Secret Access Key",
            re.compile(
                r"(?i)aws_secret_access_key[^A-Za-z0-9/+]{0,3}([A-Za-z0-9/+=]{40})"
            ),
        ),
        (
            "Generic API Key",
            re.compile(
                r"(?i)(api_key|api-key|apikey)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})"
            ),
        ),
        (
            "Password in Code",
            re.compile(
                r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']([^\"']+)[\"']"
            ),
        ),
        (
            "JWT Token",
            re.compile(
                r"eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}"
            ),
        ),
        (
            "Private Key Block",
            re.compile(r"-----BEGIN (RSA )?PRIVATE KEY-----")
        ),
    ]

    return patterns


# File discovery

def iter_files(path: Path, extensions: Iterable[str]) -> Iterable[Path]:
    """
    Yield all files to scan.
    If path is a file, yield it.
    If path is a directory, walk it and yield matching files.
    """
    if path.is_file():
        yield path
        return

    for root, _, files in os.walk(path):
        root_path = Path(root)
        for name in files:
            file_path = root_path / name
            if not extensions:
                yield file_path
            else:
                if file_path.suffix.lower() in extensions:
                    yield file_path



# Scanning logic

def scan_file(file_path: Path, patterns: List[Tuple[str, re.Pattern]]) -> List[Dict]:
    """
    Scan a single file for all patterns.

    Returns a list of matches, where each match is a dict with:
    - filename
    - line_number
    - pattern_name
    - matched_string
    """
    results: List[Dict] = []

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for pattern_name, regex in patterns:
                    for match in regex.finditer(line):
                        matched = match.group(0).strip()
                        # Truncate long matches for readability
                        if len(matched) > 120:
                            matched = matched[:117] + "..."
                        results.append(
                            {
                                "filename": str(file_path),
                                "line_number": line_number,
                                "pattern_name": pattern_name,
                                "matched_string": matched,
                            }
                        )
    except (OSError, UnicodeDecodeError) as e:
        logging.error("Could not read %s: %s", file_path, e)

    return results


def scan_path(path: Path, extensions: Iterable[str]) -> List[Dict]:
    """
    Scan a path (file or directory) and return all detected findings.
    """
    patterns = build_patterns()
    all_results: List[Dict] = []

    files = list(iter_files(path, extensions))
    if not files:
        logging.warning("No files found to scan.")
        return []

    logging.info("Scanning %d file(s)...", len(files))
    for fpath in files:
        logging.debug("Scanning %s", fpath)
        file_results = scan_file(fpath, patterns)
        all_results.extend(file_results)

    return all_results



# Reporting

def print_report(results: List[Dict]) -> None:
    """
    Print a clean, organized report to stdout.
    """
    if not results:
        print("No potential secrets found.")
        return

    print("\nPotential secrets found:\n")
    print("{:<6}  {:<8}  {:<25}  {}".format("Index", "Line", "Pattern", "Location / Match"))
    print("-" * 90)

    for idx, r in enumerate(results, start=1):
        location = f"{r['filename']}"
        line_info = f"{r['line_number']}"
        pattern = r["pattern_name"]
        match = r["matched_string"]
        print(
            "{:<6}  {:<8}  {:<25}  {}  ->  {}".format(
                idx, line_info, pattern, location, match
            )
        )

    print("\nTotal findings:", len(results))



# CLI / main

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan files or directories for hardcoded secrets."
    )
    parser.add_argument(
        "path",
        help="Path to a file or directory to scan.",
    )
    parser.add_argument(
        "-e",
        "--extensions",
        nargs="*",
        default=[
            ".py",
            ".js",
            ".ts",
            ".java",
            ".cs",
            ".env",
            ".txt",
            ".json",
            ".yml",
            ".yaml",
            ".config",
        ],
        help="File extensions to include (default: common code/config files). "
             "Use an empty list like: -e  to scan all files.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO).",
    )

    return parser.parse_args()


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(levelname)s: %(message)s",
    )


def main() -> None:
    args = parse_args()
    configure_logging(args.log_level)

    target = Path(args.path)

    if not target.exists():
        logging.error("Path does not exist: %s", target)
        return


    extensions = [ext.lower() for ext in args.extensions] if args.extensions else []

    logging.info("Starting scan on: %s", target)
    if extensions:
        logging.info("Filtering by extensions: %s", ", ".join(extensions))
    else:
        logging.info("No extension filter; scanning all files.")

    results = scan_path(target, extensions)
    print_report(results)


if __name__ == "__main__":
    main()

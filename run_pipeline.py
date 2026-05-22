from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RUNS_DIR = SCRIPT_DIR / "runs"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the full PII leak pipeline: parse source files to .txt, "
            "reprocess extracted .txt files, then write leaked_paths.txt."
        )
    )
    parser.add_argument("--input-dir", required=True, help="Directory with original files to scan recursively.")
    parser.add_argument(
        "--run-dir",
        help="Directory for this run outputs. Defaults to runs/run_<timestamp> inside the project.",
    )
    parser.add_argument(
        "--include-list",
        help="Optional UTF-8 file with relative paths to process, one path per line. Paths are relative to input-dir.",
    )
    parser.set_defaults(ocr=True)
    parser.add_argument("--ocr", dest="ocr", action="store_true", help="Enable OCR. Enabled by default.")
    parser.add_argument("--no-ocr", dest="ocr", action="store_false", help="Disable OCR.")
    parser.add_argument("--max-file-size-mb", type=float, default=100.0, help="Skip larger files. Default: 100 MB.")
    parser.add_argument("--max-rows", type=int, default=50000, help="Maximum rows for tabular files. Default: 50000.")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker processes. Default: 4.")
    parser.add_argument(
        "--file-timeout",
        type=int,
        default=600,
        help="Maximum seconds for one heavy source file. Use 0 to disable. Default: 600.",
    )
    parser.add_argument("--pdf-workers", type=int, default=2, help="Number of PDF workers. Default: 2.")
    return parser.parse_args()


def build_run_dir(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return (DEFAULT_RUNS_DIR / f"run_{timestamp}").resolve()


def run_command(command: list[str]) -> int:
    print("\n$ " + " ".join(quote_arg(item) for item in command), flush=True)
    completed = subprocess.run(command, cwd=SCRIPT_DIR, check=False)
    return completed.returncode


def quote_arg(value: str) -> str:
    if not value or any(char.isspace() for char in value):
        return repr(value)
    return value


def run_parser(args: argparse.Namespace, input_dir: Path, parsed_dir: Path) -> int:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "main.py"),
        "--input-dir",
        str(input_dir),
        "--output-dir",
        str(parsed_dir),
        "--max-file-size-mb",
        str(args.max_file_size_mb),
        "--max-rows",
        str(args.max_rows),
        "--workers",
        str(max(1, args.workers)),
        "--file-timeout",
        str(max(0, args.file_timeout)),
        "--pdf-workers",
        str(max(1, args.pdf_workers)),
    ]
    if args.include_list:
        command.extend(["--include-list", str(Path(args.include_list).expanduser().resolve())])
    if not args.ocr:
        command.append("--no-ocr")
    return run_command(command)


def run_reprocess(args: argparse.Namespace, input_dir: Path, txt_dir: Path, final_dir: Path) -> int:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "reprocess_from_txt.py"),
        "--input-dir",
        str(input_dir),
        "--txt-dir",
        str(txt_dir),
        "--output-dir",
        str(final_dir),
        "--workers",
        str(max(1, args.workers)),
    ]
    return run_command(command)


def load_report_items(report_path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuntimeError(f"Final report was not created: {report_path}") from None
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Final report is not valid JSON: {report_path}: {exc}") from exc

    items = payload.get("items", [])
    if not isinstance(items, list):
        raise RuntimeError(f"Final report has unexpected format: {report_path}")
    return [item for item in items if isinstance(item, dict)]


def build_leaked_path(row: dict[str, Any], input_dir: Path) -> str | None:
    relative_path = row.get("relative_path")
    if isinstance(relative_path, str) and relative_path.strip():
        return normalize_report_path(relative_path)

    absolute_path = row.get("path")
    if not isinstance(absolute_path, str) or not absolute_path.strip():
        return None

    path = Path(absolute_path).expanduser()
    try:
        return normalize_report_path(str(path.resolve().relative_to(input_dir)))
    except (OSError, ValueError):
        return normalize_report_path(path.name)


def normalize_report_path(value: str) -> str:
    normalized = value.replace("\\", "/").lstrip("/")
    return f"/{normalized}"


def write_leaked_paths(report_path: Path, output_path: Path, input_dir: Path) -> int:
    items = load_report_items(report_path)
    paths: list[str] = []
    seen: set[str] = set()
    for row in items:
        leaked_path = build_leaked_path(row, input_dir)
        if leaked_path and leaked_path not in seen:
            seen.add(leaked_path)
            paths.append(leaked_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return len(paths)


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir).expanduser().resolve()
    if not input_dir.exists() or not input_dir.is_dir():
        print(f"Input directory does not exist or is not a directory: {input_dir}", file=sys.stderr)
        return 2

    run_dir = build_run_dir(args.run_dir)
    parsed_dir = run_dir / "parsed"
    final_dir = run_dir / "final"
    txt_dir = parsed_dir / "extracted_texts"
    leaked_paths_path = final_dir / "leaked_paths.txt"

    parsed_dir.mkdir(parents=True, exist_ok=True)
    final_dir.mkdir(parents=True, exist_ok=True)

    print(f"Run directory: {run_dir}", flush=True)
    print(f"Parsed texts: {txt_dir}", flush=True)
    print(f"Final outputs: {final_dir}", flush=True)

    parser_code = run_parser(args, input_dir, parsed_dir)
    if parser_code != 0:
        print(f"Parser step failed with exit code {parser_code}", file=sys.stderr)
        return parser_code

    reprocess_code = run_reprocess(args, input_dir, txt_dir, final_dir)
    if reprocess_code != 0:
        print(f"Reprocess step failed with exit code {reprocess_code}", file=sys.stderr)
        return reprocess_code

    report_path = final_dir / "reports" / "final_report.json"
    try:
        leaked_count = write_leaked_paths(report_path, leaked_paths_path, input_dir)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Leaked paths written: {leaked_paths_path} ({leaked_count} paths)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

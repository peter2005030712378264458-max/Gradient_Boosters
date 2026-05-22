from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from typing import Any

from src.models import ExtractionResult, FileRecord
from src.text_extraction.text_files import extract_text_file
from src.utils.text import normalize_text, truncate_text


def extract_structured(record: FileRecord, max_rows: int) -> ExtractionResult:
    if record.extension == ".csv":
        return extract_csv(record, max_rows)
    if record.extension == ".json":
        return extract_json(record, max_items=max_rows)
    if record.extension == ".parquet":
        return extract_parquet(record, max_rows)
    return ExtractionResult("", "skipped", warnings=[f"Unsupported structured extension: {record.extension}"])


def extract_csv(record: FileRecord, max_rows: int) -> ExtractionResult:
    warnings: list[str] = []
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            sample = record.path.read_text(encoding=encoding, errors="strict")[:8192]
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            lines: list[str] = []
            with record.path.open("r", encoding=encoding, newline="") as fh:
                reader = csv.reader(fh, dialect)
                for index, row in enumerate(reader):
                    if index >= max_rows:
                        warnings.append(f"CSV truncated at {max_rows} rows")
                        break
                    lines.append(" | ".join(cell for cell in row if cell is not None))
            return ExtractionResult(
                truncate_text(normalize_text("\n".join(lines))),
                "ok",
                metadata={"encoding": encoding, "delimiter": dialect.delimiter, "rows_read": min(len(lines), max_rows), "extractor": "csv"},
                warnings=warnings,
            )
        except Exception as exc:
            warnings.append(f"CSV parse failed with {encoding}: {exc.__class__.__name__}")
    fallback = extract_text_file(record)
    fallback.warnings = warnings + ["CSV fallback to text"] + fallback.warnings
    return fallback


def extract_json(record: FileRecord, max_items: int) -> ExtractionResult:
    warnings: list[str] = []
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            data = json.loads(record.path.read_text(encoding=encoding))
            values: list[str] = []
            walk_json(data, values, max_items=max_items)
            return ExtractionResult(
                truncate_text(normalize_text("\n".join(values))),
                "ok",
                metadata={"encoding": encoding, "items_collected": len(values), "extractor": "json"},
                warnings=warnings,
            )
        except Exception as exc:
            warnings.append(f"JSON parse failed with {encoding}: {exc.__class__.__name__}")
    fallback = extract_text_file(record)
    fallback.warnings = warnings + ["JSON fallback to text"] + fallback.warnings
    return fallback


def walk_json(value: Any, output: list[str], max_items: int) -> None:
    if len(output) >= max_items:
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            output.append(str(key))
            walk_json(nested, output, max_items)
            if len(output) >= max_items:
                return
    elif isinstance(value, list):
        for item in value:
            walk_json(item, output, max_items)
            if len(output) >= max_items:
                return
    elif value is not None:
        output.append(str(value))


def extract_parquet(record: FileRecord, max_rows: int) -> ExtractionResult:
    try:
        import pandas as pd
    except Exception as exc:
        return ExtractionResult("", "skipped", warnings=[f"pandas/pyarrow unavailable for Parquet: {exc}"])

    try:
        df = pd.read_parquet(record.path)
        total_rows = len(df)
        if total_rows > max_rows:
            df = df.head(max_rows)
        lines = [f"COLUMNS: {' | '.join(map(str, df.columns))}"]
        for _, row in df.iterrows():
            lines.append(" | ".join("" if value is None else str(value) for value in row.tolist()))
        return ExtractionResult(
            truncate_text(normalize_text("\n".join(lines))),
            "ok",
            metadata={
                "columns": [str(item) for item in df.columns],
                "rows_total": total_rows,
                "rows_read": len(df),
                "extractor": "parquet",
            },
            warnings=["Parquet truncated by max_rows"] if total_rows > max_rows else [],
        )
    except Exception as exc:
        return ExtractionResult("", "error", warnings=[f"Cannot read Parquet: {exc}"])

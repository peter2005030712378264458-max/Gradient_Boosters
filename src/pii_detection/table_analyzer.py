from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.config import SENSITIVE_CATEGORIES
from src.models import FileRecord
from src.pii_detection.detector import detect_pii


TABLE_EXTENSIONS = {".csv", ".xlsx", ".xls", ".parquet"}
IDENTIFIER_CATEGORIES = {
    "full_name",
    "passport_rf",
    "foreign_id_document",
    "snils",
    "inn",
    "inn_person",
    "phone",
    "email",
    "address",
    "birth_date",
    "bank_card",
}
MAX_COLUMN_SAMPLE_VALUES = 300
MAX_ROW_DETAIL_ROWS = 5000


def analyze_table_file(record: FileRecord, max_rows: int) -> dict[str, Any] | None:
    if record.extension not in TABLE_EXTENSIONS:
        return None
    try:
        import pandas as pd
    except Exception as exc:
        return {"status": "skipped", "warnings": [f"pandas unavailable: {exc}"]}

    try:
        frames = read_table_frames(record, max_rows=max_rows)
    except Exception as exc:
        return {"status": "error", "warnings": [f"table read failed: {exc}"]}

    summary = {
        "status": "ok",
        "rows_total_known": 0,
        "rows_analyzed": 0,
        "columns_total": 0,
        "sheets": [],
        "rows_with_pii": 0,
        "rows_with_sensitive_pii": 0,
        "rows_with_sensitive_combo": 0,
        "category_row_counts": {},
        "row_combinations": {},
        "pii_columns": {},
        "sensitive_columns": [],
        "warnings": [],
    }
    category_row_counts: Counter[str] = Counter()
    row_combinations: Counter[str] = Counter()
    pii_columns: dict[str, set[str]] = defaultdict(set)
    sensitive_columns: set[str] = set()

    for sheet_name, df in frames.items():
        df = df.fillna("").astype(str)
        summary["sheets"].append(sheet_name)
        summary["rows_total_known"] += len(df)
        summary["rows_analyzed"] += len(df)
        summary["columns_total"] += len(df.columns)

        column_categories = analyze_columns(record, sheet_name, df)
        for column_name, categories in column_categories.items():
            for category in categories:
                pii_columns[category].add(column_name)
                if category in SENSITIVE_CATEGORIES or category in IDENTIFIER_CATEGORIES:
                    sensitive_columns.add(column_name)

        row_summaries, rows_scanned = analyze_rows(record, df)
        summary["row_detail_rows_scanned"] = int(summary.get("row_detail_rows_scanned", 0)) + rows_scanned
        for row_categories in row_summaries:
            summary["rows_with_pii"] += 1
            for category in row_categories:
                category_row_counts[category] += 1
            if row_categories & SENSITIVE_CATEGORIES:
                summary["rows_with_sensitive_pii"] += 1
            if is_sensitive_row_combo(row_categories):
                summary["rows_with_sensitive_combo"] += 1
                combo = "+".join(sorted(row_categories & IDENTIFIER_CATEGORIES))
                if combo:
                    row_combinations[combo] += 1

    summary["category_row_counts"] = dict(category_row_counts)
    summary["row_combinations"] = dict(row_combinations.most_common(50))
    summary["pii_columns"] = {category: sorted(columns)[:50] for category, columns in pii_columns.items()}
    summary["sensitive_columns"] = sorted(sensitive_columns)[:100]
    rows_analyzed = max(int(summary["rows_analyzed"] or 0), 1)
    summary["pii_row_ratio"] = round(int(summary["rows_with_pii"]) / rows_analyzed, 4)
    summary["sensitive_row_ratio"] = round(int(summary["rows_with_sensitive_pii"]) / rows_analyzed, 4)
    summary["combo_row_ratio"] = round(int(summary["rows_with_sensitive_combo"]) / rows_analyzed, 4)
    summary["pii_column_count"] = sum(len(columns) for columns in summary["pii_columns"].values())
    summary["sensitive_column_count"] = len(summary["sensitive_columns"])
    if summary["rows_analyzed"] >= max_rows:
        summary["warnings"].append(f"Table analysis limited to max_rows={max_rows}")
    if int(summary.get("row_detail_rows_scanned", 0)) < int(summary["rows_analyzed"]):
        summary["warnings"].append(
            f"Row-level table detail limited to {summary['row_detail_rows_scanned']} rows; full-file PII detection still used extracted text"
        )
    return summary


def read_table_frames(record: FileRecord, max_rows: int) -> dict[str, Any]:
    import pandas as pd

    if record.extension == ".csv":
        return {"csv": read_csv_frame(record.path, max_rows)}
    if record.extension in {".xlsx", ".xls"}:
        frames = pd.read_excel(record.path, sheet_name=None, header=None, dtype=str, nrows=max_rows)
        return {str(name): frame for name, frame in frames.items()}
    if record.extension == ".parquet":
        df = pd.read_parquet(record.path)
        if len(df) > max_rows:
            df = df.head(max_rows)
        return {"parquet": df}
    return {}


def read_csv_frame(path: Path, max_rows: int) -> Any:
    import pandas as pd

    errors: list[str] = []
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            return pd.read_csv(path, sep=None, engine="python", dtype=str, keep_default_na=False, nrows=max_rows, encoding=encoding)
        except Exception as exc:
            errors.append(f"{encoding}: {exc.__class__.__name__}")
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        for sep in (",", ";", "\t", "|"):
            try:
                return pd.read_csv(path, sep=sep, dtype=str, keep_default_na=False, nrows=max_rows, encoding=encoding)
            except Exception:
                continue
    raise ValueError("; ".join(errors))


def analyze_columns(record: FileRecord, sheet_name: str, df: Any) -> dict[str, set[str]]:
    column_categories: dict[str, set[str]] = {}
    for column in df.columns:
        column_label = str(column)
        values = df[column].dropna().astype(str).head(MAX_COLUMN_SAMPLE_VALUES).tolist()
        probe = " | ".join([column_label] + values)
        pii = detect_pii(record, probe, {})
        if pii.categories:
            output_name = f"{sheet_name}:{column_label}"
            column_categories[output_name] = set(pii.categories)
    return column_categories


def analyze_rows(record: FileRecord, df: Any) -> tuple[list[set[str]], int]:
    rows_to_scan = min(len(df), MAX_ROW_DETAIL_ROWS)
    if rows_to_scan <= 0:
        return [], 0

    row_summaries: list[set[str]] = []
    columns = [str(column) for column in df.columns]
    for row_offset, (_, row) in enumerate(df.head(rows_to_scan).iterrows(), start=1):
        row_text = " | ".join(
            f"{column}: {value}"
            for column, value in zip(columns, row.tolist())
            if value and str(value).lower() != "nan"
        )
        if not row_text.strip():
            continue
        row_pii = detect_pii(record, f"ROW {row_offset}: {row_text}", {})
        row_categories = set(row_pii.categories)
        if not row_categories:
            continue
        row_summaries.append(row_categories)

    return row_summaries, rows_to_scan


def is_sensitive_row_combo(categories: set[str]) -> bool:
    if "full_name" in categories and categories & SENSITIVE_CATEGORIES:
        return True
    if len(categories & SENSITIVE_CATEGORIES) >= 2:
        return True
    return len(categories & IDENTIFIER_CATEGORIES) >= 3

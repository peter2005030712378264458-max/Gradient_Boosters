from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from src.models import ProcessingStats


CSV_COLUMNS = [
    "путь",
    "формат_файла",
    "тип_документа",
    "категории_ПДн",
    "количество_находок",
    "риск_утечки",
    "обоснование",
    "рекомендация",
]


def write_reports(reports_dir: Path, rows: list[dict[str, Any]], stats: ProcessingStats) -> None:
    write_csv(reports_dir / "final_report.csv", rows)
    write_json(reports_dir / "final_report.json", rows, stats)
    write_markdown(reports_dir / "final_report.md", rows, stats)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "путь": row["path"],
                    "формат_файла": row["file_format"],
                    "тип_документа": row["document_type"],
                    "категории_ПДн": ", ".join(row["pii_categories"]),
                    "количество_находок": "; ".join(f"{key}={value}" for key, value in row["finding_counts"].items()),
                    "риск_утечки": f"{row['risk_level']} ({row['risk_score']})",
                    "обоснование": "; ".join(row["reasons"]),
                    "рекомендация": row["recommendation"],
                }
            )


def write_json(path: Path, rows: list[dict[str, Any]], stats: ProcessingStats) -> None:
    payload = {"stats": stats.__dict__, "items": rows}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_markdown(path: Path, rows: list[dict[str, Any]], stats: ProcessingStats) -> None:
    lines = [
        "# Итоговый отчет по высокорисковым файлам",
        "",
        "Подход: рекурсивное сканирование, извлечение текстового слоя, поиск категорий ПДн, прозрачный риск-скоринг.",
        "",
        f"- Всего файлов: {stats.total_files}",
        f"- Обработано: {stats.processed_files}",
        f"- Пропущено: {stats.skipped_files}",
        f"- Ошибок: {stats.error_files}",
        f"- В отчете: {len(rows)}",
        "",
        "| Путь | Формат | Тип документа | Категории ПДн | Риск | Обоснование | Рекомендация |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| {path} | {fmt} | {doc} | {cats} | {risk} | {reasons} | {rec} |".format(
                path=escape_md(row["path"]),
                fmt=escape_md(row["file_format"]),
                doc=escape_md(row["document_type"]),
                cats=escape_md(", ".join(row["pii_categories"])),
                risk=escape_md(f"{row['risk_level']} ({row['risk_score']})"),
                reasons=escape_md("; ".join(row["reasons"])),
                rec=escape_md(row["recommendation"]),
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def escape_md(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")

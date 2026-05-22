from __future__ import annotations

from src.models import ExtractionResult, FileRecord
from src.utils.text import normalize_text, truncate_text


ENCODINGS = ("utf-8", "utf-8-sig", "cp1251", "latin-1")


def extract_text_file(record: FileRecord) -> ExtractionResult:
    warnings: list[str] = []
    for encoding in ENCODINGS:
        try:
            text = record.path.read_text(encoding=encoding, errors="strict")
            return ExtractionResult(
                truncate_text(normalize_text(text)),
                "ok",
                metadata={"encoding": encoding, "extractor": "text"},
                warnings=warnings,
            )
        except UnicodeDecodeError:
            warnings.append(f"Encoding failed: {encoding}")
        except OSError as exc:
            return ExtractionResult("", "error", warnings=[f"Cannot read text file: {exc}"])
    try:
        text = record.path.read_text(encoding="latin-1", errors="ignore")
        return ExtractionResult(
            truncate_text(normalize_text(text)),
            "ok",
            metadata={"encoding": "latin-1-ignore", "extractor": "text"},
            warnings=warnings + ["Used latin-1 with ignored errors"],
        )
    except OSError as exc:
        return ExtractionResult("", "error", warnings=[f"Cannot read text file: {exc}"])

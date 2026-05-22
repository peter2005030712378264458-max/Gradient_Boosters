from __future__ import annotations

from src.models import ExtractionResult, FileRecord
from src.text_extraction.text_files import extract_text_file
from src.utils.text import normalize_text, truncate_text


def extract_html(record: FileRecord) -> ExtractionResult:
    raw = extract_text_file(record)
    if raw.status != "ok":
        return raw
    try:
        from bs4 import BeautifulSoup
    except Exception as exc:
        raw.metadata["extractor"] = "html-as-text"
        raw.warnings.append(f"BeautifulSoup unavailable: {exc}")
        return raw

    try:
        soup = BeautifulSoup(raw.text, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text("\n")
        return ExtractionResult(
            truncate_text(normalize_text(text)),
            "ok",
            metadata={"extractor": "html", "encoding": raw.metadata.get("encoding")},
            warnings=raw.warnings,
        )
    except Exception as exc:
        raw.warnings.append(f"HTML parse failed, used raw text: {exc}")
        return raw

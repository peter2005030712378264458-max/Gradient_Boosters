from __future__ import annotations

from src.config import HTML_EXTENSIONS, IMAGE_EXTENSIONS, OFFICE_EXTENSIONS, PDF_EXTENSIONS, STRUCTURED_EXTENSIONS, TEXT_EXTENSIONS, VIDEO_EXTENSIONS
from src.models import ExtractionResult, FileRecord
from src.text_extraction.docling_extractor import extract_with_docling
from src.text_extraction.html_files import extract_html
from src.text_extraction.image_files import extract_image
from src.text_extraction.office_files import extract_office
from src.text_extraction.pdf_files import extract_pdf
from src.text_extraction.structured_files import extract_structured
from src.text_extraction.text_files import extract_text_file
from src.text_extraction.video_files import extract_video


def extract_text(record: FileRecord, use_ocr: bool, max_rows: int) -> ExtractionResult:
    warnings: list[str] = []

    if record.extension in OFFICE_EXTENSIONS | HTML_EXTENSIONS:
        docling_result = extract_with_docling(record)
        if docling_result.status == "ok" and docling_result.text.strip():
            return docling_result
        warnings.extend([f"docling: {item}" for item in docling_result.warnings])

    if record.extension in TEXT_EXTENSIONS:
        result = extract_text_file(record)
    elif record.extension in STRUCTURED_EXTENSIONS:
        result = extract_structured(record, max_rows=max_rows)
    elif record.extension in OFFICE_EXTENSIONS:
        result = extract_office(record, max_rows=max_rows)
    elif record.extension in PDF_EXTENSIONS:
        result = extract_pdf(record, use_ocr=use_ocr)
    elif record.extension in HTML_EXTENSIONS:
        result = extract_html(record)
    elif record.extension in IMAGE_EXTENSIONS:
        result = extract_image(record, use_ocr=use_ocr)
    elif record.extension in VIDEO_EXTENSIONS:
        result = extract_video(record, use_ocr=use_ocr)
    else:
        result = ExtractionResult("", "skipped", warnings=[f"Unsupported extension: {record.extension}"])

    result.warnings = warnings + result.warnings
    return result

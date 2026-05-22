from __future__ import annotations

from src.models import ExtractionResult, FileRecord
from src.utils.text import normalize_text, truncate_text


def extract_pdf(record: FileRecord, use_ocr: bool = False) -> ExtractionResult:
    warnings: list[str] = []
    text, metadata, error = extract_pdf_pdfplumber(record)
    if text.strip():
        return ExtractionResult(truncate_text(normalize_text(text)), "ok", metadata=metadata, warnings=warnings)
    if error:
        warnings.append(error)

    text, metadata, error = extract_pdf_pypdf(record)
    if text.strip():
        return ExtractionResult(truncate_text(normalize_text(text)), "ok", metadata=metadata, warnings=warnings)
    if error:
        warnings.append(error)

    if use_ocr:
        text, ocr_metadata, error = extract_pdf_ocr(record)
        warnings.extend(ocr_metadata.pop("warnings", []))
        if text.strip():
            return ExtractionResult(
                truncate_text(normalize_text(text)),
                "ok",
                metadata=ocr_metadata,
                warnings=warnings,
            )
        if error:
            warnings.append(error)

    metadata["possible_scanned_pdf"] = True
    return ExtractionResult("", "ok", metadata=metadata, warnings=warnings + ["PDF text layer is empty; possible scanned PDF"])


def extract_pdf_pdfplumber(record: FileRecord) -> tuple[str, dict, str | None]:
    try:
        import pdfplumber
    except Exception as exc:
        return "", {"extractor": "pdfplumber"}, f"pdfplumber unavailable: {exc.__class__.__name__}"

    try:
        pages = []
        with pdfplumber.open(record.path) as pdf:
            for page in pdf.pages:
                pages.append(page.extract_text() or "")
        return "\n\n".join(pages), {"pages": len(pages), "extractor": "pdfplumber"}, None
    except Exception as exc:
        return "", {"extractor": "pdfplumber"}, f"pdfplumber failed: {exc}"


def extract_pdf_pypdf(record: FileRecord) -> tuple[str, dict, str | None]:
    try:
        from pypdf import PdfReader
    except Exception as exc:
        return "", {"extractor": "pypdf"}, f"pypdf unavailable: {exc.__class__.__name__}"

    try:
        reader = PdfReader(str(record.path))
        pages = [(page.extract_text() or "") for page in reader.pages]
        return "\n\n".join(pages), {"pages": len(pages), "extractor": "pypdf"}, None
    except Exception as exc:
        return "", {"extractor": "pypdf"}, f"pypdf failed: {exc}"


def extract_pdf_ocr(record: FileRecord) -> tuple[str, dict, str | None]:
    try:
        import pypdfium2 as pdfium
        import pytesseract
    except Exception as exc:
        return "", {"extractor": "pdf-ocr", "ocr_used": False}, f"PDF OCR dependencies unavailable: {exc.__class__.__name__}"

    try:
        pdf = pdfium.PdfDocument(str(record.path))
        page_count = len(pdf)
        texts: list[str] = []
        page_warnings: list[str] = []
        for index in range(page_count):
            try:
                page = pdf[index]
                image = page.render(scale=2.5).to_pil()
                try:
                    page_text = pytesseract.image_to_string(image, lang="rus+eng")
                except Exception:
                    page_warnings.append(f"Page {index + 1}: rus+eng OCR failed, retrying with rus")
                    page_text = pytesseract.image_to_string(image, lang="rus")
                texts.append(page_text or "")
            except Exception as exc:
                page_warnings.append(f"Page {index + 1}: OCR failed: {exc}")
        text = "\n\n".join(texts)
        metadata = {
            "pages": page_count,
            "extractor": "pdf-ocr-tesseract",
            "ocr_used": True,
            "ocr_language": "rus+eng",
            "warnings": page_warnings,
        }
        if text.strip():
            return text, metadata, None
        return "", metadata, "PDF OCR returned empty text"
    except Exception as exc:
        return "", {"extractor": "pdf-ocr-tesseract", "ocr_used": False}, f"PDF OCR failed: {exc}"

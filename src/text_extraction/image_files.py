from __future__ import annotations

from src.models import ExtractionResult, FileRecord
from src.utils.text import normalize_text, truncate_text


def extract_image(record: FileRecord, use_ocr: bool) -> ExtractionResult:
    metadata = {"extractor": "image", "ocr_used": False}
    if not use_ocr:
        return ExtractionResult("", "ok", metadata=metadata, warnings=["OCR disabled"])

    try:
        from PIL import Image
        import pytesseract
    except Exception as exc:
        return ExtractionResult("", "ok", metadata=metadata, warnings=[f"OCR unavailable: {exc.__class__.__name__}"])

    try:
        with Image.open(record.path) as image:
            metadata.update({"image_size": image.size, "image_mode": image.mode})
            text, language, warnings = image_to_string_with_fallback(pytesseract, image)
            metadata["ocr_language"] = language
        metadata["ocr_used"] = True
        return ExtractionResult(truncate_text(normalize_text(text)), "ok", metadata=metadata, warnings=warnings)
    except Exception as exc:
        return ExtractionResult("", "ok", metadata=metadata, warnings=[f"OCR failed: {exc}"])


def image_to_string_with_fallback(pytesseract_module, image) -> tuple[str, str, list[str]]:
    warnings: list[str] = []
    for language in ("rus+eng", "rus", "eng"):
        try:
            return pytesseract_module.image_to_string(image, lang=language), language, warnings
        except Exception as exc:
            warnings.append(f"OCR failed for {language}: {exc.__class__.__name__}")
    return pytesseract_module.image_to_string(image), "default", warnings + ["OCR used default language"]

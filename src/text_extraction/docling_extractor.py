from __future__ import annotations

import os

from src.models import ExtractionResult, FileRecord
from src.utils.text import normalize_text, truncate_text


_CONVERTER = None


def get_docling_converter():
    global _CONVERTER
    if _CONVERTER is None:
        os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")
        from docling.datamodel.base_models import InputFormat
        from docling.datamodel.pipeline_options import AcceleratorDevice, AcceleratorOptions, PdfPipelineOptions
        from docling.document_converter import DocumentConverter
        from docling.document_converter import PdfFormatOption

        pdf_options = PdfPipelineOptions(
            accelerator_options=AcceleratorOptions(device=AcceleratorDevice.CPU)
        )

        _CONVERTER = DocumentConverter(
            format_options={
                InputFormat.PDF: PdfFormatOption(pipeline_options=pdf_options),
            }
        )
    return _CONVERTER


def extract_with_docling(record: FileRecord) -> ExtractionResult:
    try:
        converter = get_docling_converter()
    except Exception as exc:
        return ExtractionResult("", "skipped", warnings=[f"Docling unavailable: {exc.__class__.__name__}"])

    try:
        converted = converter.convert(str(record.path))
        document = converted.document
        text = ""
        if hasattr(document, "export_to_markdown"):
            text = document.export_to_markdown()
        elif hasattr(document, "export_to_text"):
            text = document.export_to_text()
        if not text:
            return ExtractionResult("", "skipped", metadata={"docling_used": True}, warnings=["Docling returned empty text"])
        return ExtractionResult(
            truncate_text(normalize_text(text)),
            "ok",
            metadata={"docling_used": True, "extractor": "docling"},
            warnings=[],
        )
    except Exception as exc:
        return ExtractionResult("", "skipped", metadata={"docling_used": False}, warnings=[f"Docling failed: {exc}"])

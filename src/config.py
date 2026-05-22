from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"

TEXT_EXTENSIONS = {".txt", ".md", ".log"}
STRUCTURED_EXTENSIONS = {".csv", ".json", ".parquet"}
OFFICE_EXTENSIONS = {".docx", ".doc", ".rtf", ".xlsx", ".xls"}
PDF_EXTENSIONS = {".pdf"}
HTML_EXTENSIONS = {".html", ".htm"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".gif"}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".mpeg", ".mpg"}

SUPPORTED_EXTENSIONS = (
    TEXT_EXTENSIONS
    | STRUCTURED_EXTENSIONS
    | OFFICE_EXTENSIONS
    | PDF_EXTENSIONS
    | HTML_EXTENSIONS
    | IMAGE_EXTENSIONS
    | VIDEO_EXTENSIONS
)

SENSITIVE_CATEGORIES = {
    "passport_rf",
    "foreign_id_document",
    "snils",
    "inn",
    "inn_person",
    "driver_license",
    "mrz",
    "bank_card",
    "bank_account",
    "bik",
    "cvv",
    "biometric",
    "health",
    "religion",
    "political_views",
    "nationality",
    "race",
}

MEDIUM_RISK_THRESHOLD = 6
HIGH_RISK_THRESHOLD = 11


@dataclass(frozen=True)
class OutputDirs:
    root: Path
    extracted_texts: Path
    pii_findings: Path
    reports: Path
    logs: Path


def ensure_output_dirs(output_dir: Path) -> OutputDirs:
    dirs = OutputDirs(
        root=output_dir,
        extracted_texts=output_dir / "extracted_texts",
        pii_findings=output_dir / "pii_findings",
        reports=output_dir / "reports",
        logs=output_dir / "logs",
    )
    for path in (dirs.root, dirs.extracted_texts, dirs.pii_findings, dirs.reports, dirs.logs):
        path.mkdir(parents=True, exist_ok=True)
    return dirs

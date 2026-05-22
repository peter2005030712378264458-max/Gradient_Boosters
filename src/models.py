from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FileRecord:
    path: Path
    relative_path: str
    extension: str
    size_bytes: int
    modified_at: float | None = None
    status: str = "pending"
    error: str | None = None


@dataclass
class ExtractionResult:
    text: str
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class CategoryFinding:
    count: int = 0
    samples_masked: list[str] = field(default_factory=list)


@dataclass
class PIIResult:
    file_path: str
    relative_path: str
    file_format: str
    categories: dict[str, CategoryFinding] = field(default_factory=dict)
    features: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskResult:
    score: int
    level: str
    include_in_report: bool
    reasons: list[str]
    recommendation: str


@dataclass
class ProcessingStats:
    total_files: int = 0
    processed_files: int = 0
    skipped_files: int = 0
    error_files: int = 0

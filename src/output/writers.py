from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from src.models import FileRecord, PIIResult
from src.utils.file_id import safe_file_id


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
        os.replace(temp_path, path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def write_extracted_text(output_dir: Path, record: FileRecord, text: str) -> Path:
    path = output_dir / f"{safe_file_id(record)}.txt"
    atomic_write_text(path, text or "")
    return path


def write_pii_findings(output_dir: Path, record: FileRecord, pii_result: PIIResult) -> Path:
    path = output_dir / f"{safe_file_id(record)}.json"
    atomic_write_text(path, json.dumps(asdict(pii_result), ensure_ascii=False, indent=2))
    return path

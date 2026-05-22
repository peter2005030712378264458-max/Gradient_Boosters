from __future__ import annotations

import hashlib
import re

from src.models import FileRecord


def safe_file_id(record: FileRecord) -> str:
    normalized = record.relative_path.replace("\\", "/")
    slug = re.sub(r"[^A-Za-zА-Яа-я0-9._-]+", "__", normalized).strip("._")
    digest = hashlib.sha1(normalized.encode("utf-8", errors="ignore")).hexdigest()[:12]
    if len(slug) > 120:
        slug = slug[:120]
    return f"{slug or 'file'}__{digest}"

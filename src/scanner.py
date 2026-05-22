from __future__ import annotations

from pathlib import Path

from src.config import SUPPORTED_EXTENSIONS
from src.models import FileRecord


def scan_files(input_dir: Path, max_file_size_mb: float) -> list[FileRecord]:
    records: list[FileRecord] = []
    max_bytes = int(max_file_size_mb * 1024 * 1024)

    for path in input_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
            extension = path.suffix.lower()
            relative_path = str(path.relative_to(input_dir))
            record = FileRecord(
                path=path.resolve(),
                relative_path=relative_path,
                extension=extension,
                size_bytes=stat.st_size,
                modified_at=stat.st_mtime,
            )
            if path.name.startswith("~$"):
                record.status = "skipped"
                record.error = "Temporary Office lock file"
            elif extension not in SUPPORTED_EXTENSIONS:
                record.status = "skipped"
                record.error = f"Unsupported extension: {extension or '<none>'}"
            elif stat.st_size > max_bytes:
                record.status = "skipped"
                record.error = f"File is larger than limit: {stat.st_size} bytes"
            records.append(record)
        except OSError as exc:
            records.append(
                FileRecord(
                    path=path,
                    relative_path=str(path),
                    extension=path.suffix.lower(),
                    size_bytes=0,
                    status="skipped",
                    error=f"Cannot stat file: {exc}",
                )
            )
    return records

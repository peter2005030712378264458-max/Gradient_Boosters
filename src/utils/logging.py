from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class JsonlLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write(self, file_path: Path, stage: str, status: str, message: str) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file_path": str(file_path),
            "stage": stage,
            "status": status,
            "message": message,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

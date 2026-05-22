from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from src.config import DEFAULT_OUTPUT_DIR, OutputDirs, ensure_output_dirs
from src.models import FileRecord, PIIResult, ProcessingStats, RiskResult
from src.output.reports import write_reports
from src.output.writers import atomic_write_text
from src.pii_detection.detector import detect_pii
from src.risk.classifier import classify_risk
from src.risk.document_type import detect_document_type
from src.utils.file_id import safe_file_id
from src.utils.logging import JsonlLogger


REPORT_FLUSH_EVERY_FILES = 50


@dataclass
class TextJob:
    index: int
    record: FileRecord
    text_path: Path


@dataclass
class TextProcessingOutcome:
    stats_bucket: str
    log_stage: str
    log_status: str
    log_message: str
    text_path: str
    pii_result: PIIResult | None = None
    document_type: str | None = None
    risk: RiskResult | None = None


def default_worker_count() -> int:
    return max(1, min(4, os.cpu_count() or 1))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Re-run PII detection from already extracted .txt files without parsing original documents."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Original source directory. Used only to restore original file paths from extracted text file ids.",
    )
    parser.add_argument(
        "--txt-dir",
        required=True,
        help="Directory with extracted .txt files, for example output/extracted_texts.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory where pii_findings, reports, and logs will be written.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=default_worker_count(),
        help="Number of text files to analyze in parallel. Use 1 for sequential processing.",
    )
    return parser.parse_args()


def scan_original_records(input_dir: Path) -> dict[str, FileRecord]:
    records_by_id: dict[str, FileRecord] = {}
    for path in input_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
            record = FileRecord(
                path=path.resolve(),
                relative_path=str(path.relative_to(input_dir)),
                extension=path.suffix.lower(),
                size_bytes=stat.st_size,
                modified_at=stat.st_mtime,
            )
        except OSError:
            continue

        for relative_path_variant in unicode_path_variants(record.relative_path):
            variant_record = FileRecord(
                path=record.path,
                relative_path=relative_path_variant,
                extension=record.extension,
                size_bytes=record.size_bytes,
                modified_at=record.modified_at,
            )
            file_id = safe_file_id(variant_record)
            records_by_id.setdefault(file_id, record)
    return records_by_id


def unicode_path_variants(relative_path: str) -> set[str]:
    normalized = relative_path.replace("\\", "/")
    return {
        normalized,
        unicodedata.normalize("NFC", normalized),
        unicodedata.normalize("NFD", normalized),
    }


def build_jobs(text_dir: Path, records_by_id: dict[str, FileRecord]) -> tuple[list[TextJob], list[Path]]:
    jobs: list[TextJob] = []
    unmatched_texts: list[Path] = []
    for text_path in sorted(text_dir.glob("*.txt")):
        record = records_by_id.get(text_path.stem)
        if record is None:
            unmatched_texts.append(text_path)
            record = build_text_only_record(text_path)
        jobs.append(TextJob(index=len(jobs), record=record, text_path=text_path.resolve()))
    return jobs, unmatched_texts


def build_text_only_record(text_path: Path) -> FileRecord:
    stat = text_path.stat()
    stem_without_hash = text_path.stem.rsplit("__", 1)[0]
    inferred_relative_path = stem_without_hash.replace("__", "/")
    extension = Path(inferred_relative_path).suffix.lower() or ".txt"
    return FileRecord(
        path=text_path.resolve(),
        relative_path=f"text-only/{inferred_relative_path}",
        extension=extension,
        size_bytes=stat.st_size,
        modified_at=stat.st_mtime,
    )


def process_text_job(job: TextJob) -> TextProcessingOutcome:
    try:
        text = job.text_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return TextProcessingOutcome(
            stats_bucket="error",
            log_stage="text_read",
            log_status="error",
            log_message=f"Cannot read extracted text: {exc}",
            text_path=str(job.text_path),
        )

    extraction_metadata = {
        "extractor": "preextracted-text",
        "source_text_path": str(job.text_path),
        "parsing_skipped": True,
    }
    try:
        pii_result = detect_pii(job.record, text, extraction_metadata)
        document_type = detect_document_type(job.record, text, extraction_metadata, pii_result)
        risk = classify_risk(job.record, text, extraction_metadata, pii_result, document_type)
        return TextProcessingOutcome(
            stats_bucket="processed",
            log_stage="txt_pipeline",
            log_status="ok",
            log_message=f"risk={risk.level}; score={risk.score}",
            text_path=str(job.text_path),
            pii_result=pii_result,
            document_type=document_type,
            risk=risk,
        )
    except Exception as exc:
        return TextProcessingOutcome(
            stats_bucket="error",
            log_stage="txt_pipeline",
            log_status="error",
            log_message=repr(exc),
            text_path=str(job.text_path),
        )


def write_pii_findings(output_dir: Path, record: FileRecord, pii_result: PIIResult) -> Path:
    path = output_dir / f"{safe_file_id(record)}.json"
    atomic_write_text(path, json.dumps(asdict(pii_result), ensure_ascii=False, indent=2))
    return path


def build_report_row(
    record: FileRecord,
    pii_result: PIIResult,
    risk: RiskResult,
    document_type: str,
    text_path: Path,
    findings_path: Path,
) -> dict[str, Any]:
    return {
        "path": str(record.path),
        "relative_path": record.relative_path,
        "file_format": record.extension,
        "document_type": document_type,
        "pii_categories": sorted(pii_result.categories.keys()),
        "finding_counts": {name: item.count for name, item in pii_result.categories.items()},
        "features": pii_result.features,
        "risk_level": risk.level,
        "risk_score": risk.score,
        "reasons": risk.reasons,
        "recommendation": risk.recommendation,
        "table_analysis": pii_result.metadata.get("table_analysis"),
        "extracted_text_path": str(text_path),
        "pii_findings_path": str(findings_path),
    }


def report_rows_in_scan_order(report_rows_by_index: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    return [report_rows_by_index[index] for index in sorted(report_rows_by_index)]


def apply_outcome(
    *,
    job: TextJob,
    outcome: TextProcessingOutcome,
    dirs: OutputDirs,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
) -> None:
    if outcome.stats_bucket == "processed":
        if outcome.pii_result is None or outcome.risk is None or outcome.document_type is None:
            stats.error_files += 1
            logger.write(job.record.path, "txt_pipeline", "error", "processed outcome is missing required payload")
            return

        findings_path = write_pii_findings(dirs.pii_findings, job.record, outcome.pii_result)
        stats.processed_files += 1
        if outcome.risk.include_in_report:
            report_rows_by_index[job.index] = build_report_row(
                job.record,
                outcome.pii_result,
                outcome.risk,
                outcome.document_type,
                job.text_path,
                findings_path,
            )
    else:
        stats.error_files += 1

    logger.write(job.record.path, outcome.log_stage, outcome.log_status, outcome.log_message)


def process_jobs(
    *,
    jobs: list[TextJob],
    workers: int,
    dirs: OutputDirs,
    logger: JsonlLogger,
    stats: ProcessingStats,
) -> list[dict[str, Any]]:
    report_rows_by_index: dict[int, dict[str, Any]] = {}
    jobs_by_index = {job.index: job for job in jobs}

    if workers <= 1 or len(jobs) <= 1:
        for offset, job in enumerate(jobs, start=1):
            print(f"[{offset}/{len(jobs)}] Analyzing {job.record.relative_path}", flush=True)
            outcome = process_text_job(job)
            apply_outcome(
                job=job,
                outcome=outcome,
                dirs=dirs,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
            )
            if offset % REPORT_FLUSH_EVERY_FILES == 0:
                write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)
        return report_rows_in_scan_order(report_rows_by_index)

    worker_count = min(workers, len(jobs))
    print(f"Analyzing {len(jobs)} extracted texts with {worker_count} workers", flush=True)
    try:
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            futures = {executor.submit(process_text_job, job): job.index for job in jobs}
            completed = 0
            for future in as_completed(futures):
                job = jobs_by_index[futures[future]]
                completed += 1
                try:
                    outcome = future.result()
                except Exception as exc:
                    outcome = TextProcessingOutcome(
                        stats_bucket="error",
                        log_stage="txt_pipeline",
                        log_status="error",
                        log_message=repr(exc),
                        text_path=str(job.text_path),
                    )
                print(f"[{completed}/{len(jobs)}] Finished {job.record.relative_path}", flush=True)
                apply_outcome(
                    job=job,
                    outcome=outcome,
                    dirs=dirs,
                    logger=logger,
                    stats=stats,
                    report_rows_by_index=report_rows_by_index,
                )
                if completed % REPORT_FLUSH_EVERY_FILES == 0:
                    write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)
    except (OSError, PermissionError) as exc:
        print(f"Process pool unavailable, falling back to sequential processing: {exc!r}", flush=True)
        for offset, job in enumerate(jobs, start=1):
            print(f"[{offset}/{len(jobs)}] Analyzing {job.record.relative_path}", flush=True)
            outcome = process_text_job(job)
            apply_outcome(
                job=job,
                outcome=outcome,
                dirs=dirs,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
            )
            if offset % REPORT_FLUSH_EVERY_FILES == 0:
                write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)

    return report_rows_in_scan_order(report_rows_by_index)


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir).expanduser().resolve()
    text_dir = Path(args.txt_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    workers = max(1, args.workers)

    if not input_dir.exists() or not input_dir.is_dir():
        print(f"Input directory does not exist or is not a directory: {input_dir}", file=sys.stderr)
        return 2
    if not text_dir.exists() or not text_dir.is_dir():
        print(f"Text directory does not exist or is not a directory: {text_dir}", file=sys.stderr)
        return 2

    dirs = ensure_output_dirs(output_dir)
    logger = JsonlLogger(dirs.logs / "reprocess_from_txt_log.jsonl")

    records_by_id = scan_original_records(input_dir)
    jobs, unmatched_texts = build_jobs(text_dir, records_by_id)
    stats = ProcessingStats(total_files=len(jobs), skipped_files=0)

    for text_path in unmatched_texts:
        logger.write(text_path, "mapping", "text_only", "No original file matched this extracted text id; analyzing extracted text")

    print(
        f"Matched {len(jobs) - len(unmatched_texts)} extracted texts to original files; "
        f"{len(unmatched_texts)} extracted texts will be analyzed as text-only",
        flush=True,
    )
    write_reports(dirs.reports, [], stats)
    rows = process_jobs(jobs=jobs, workers=workers, dirs=dirs, logger=logger, stats=stats)
    write_reports(dirs.reports, rows, stats)
    print(
        f"Done. processed={stats.processed_files}, skipped={stats.skipped_files}, "
        f"errors={stats.error_files}, report_items={len(rows)}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

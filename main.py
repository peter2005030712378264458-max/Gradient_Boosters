from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import queue
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from src.config import (
    DEFAULT_OUTPUT_DIR,
    HTML_EXTENSIONS,
    IMAGE_EXTENSIONS,
    OFFICE_EXTENSIONS,
    OutputDirs,
    PDF_EXTENSIONS,
    VIDEO_EXTENSIONS,
    ensure_output_dirs,
)
from src.models import FileRecord, PIIResult, ProcessingStats, RiskResult
from src.output.reports import write_reports
from src.output.writers import write_extracted_text, write_pii_findings
from src.pii_detection.detector import detect_pii
from src.pii_detection.table_analyzer import analyze_table_file
from src.risk.classifier import classify_risk
from src.risk.document_type import detect_document_type
from src.scanner import scan_files
from src.text_extraction.dispatcher import extract_text
from src.utils.logging import JsonlLogger


REPORT_FLUSH_EVERY_FILES = 10
DEFAULT_FILE_TIMEOUT_SECONDS = 600
DEFAULT_PDF_WORKERS = 2


@dataclass
class FileProcessingOutcome:
    stats_bucket: str
    log_stage: str
    log_status: str
    log_message: str
    extracted_text: str | None = None
    pii_result: PIIResult | None = None
    document_type: str | None = None
    risk: RiskResult | None = None


@dataclass
class ActiveIsolatedTask:
    index: int
    record: FileRecord
    process: mp.Process
    result_queue: mp.Queue
    deadline: float | None


HEAVY_PROCESS_EXTENSIONS = OFFICE_EXTENSIONS | PDF_EXTENSIONS | HTML_EXTENSIONS | IMAGE_EXTENSIONS | VIDEO_EXTENSIONS


def default_worker_count() -> int:
    return max(1, min(4, os.cpu_count() or 1))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a file storage, extract text, detect PII categories, and report high-risk files."
    )
    parser.add_argument("--input-dir", required=True, help="Directory to scan recursively.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for extracted data and reports.")
    parser.add_argument(
        "--include-list",
        help="Optional UTF-8 file with relative paths to process, one path per line. Paths are relative to input-dir.",
    )
    parser.set_defaults(ocr=True)
    parser.add_argument("--ocr", dest="ocr", action="store_true", help="Enable OCR for images and scanned PDFs. Enabled by default.")
    parser.add_argument("--no-ocr", dest="ocr", action="store_false", help="Disable OCR for images and scanned PDFs.")
    parser.add_argument(
        "--max-file-size-mb",
        type=float,
        default=100.0,
        help="Skip files larger than this size. Default: 100 MB.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=50000,
        help="Maximum rows to read from large tabular files. Default: 50000.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=default_worker_count(),
        help="Number of files to process in parallel. Use 1 for sequential processing.",
    )
    parser.add_argument(
        "--file-timeout",
        type=int,
        default=DEFAULT_FILE_TIMEOUT_SECONDS,
        help="Maximum seconds for one heavy file before it is skipped as an error. Use 0 to disable. Default: 600.",
    )
    parser.add_argument(
        "--pdf-workers",
        type=int,
        default=DEFAULT_PDF_WORKERS,
        help="Number of PDF files to process in parallel. Default: 2.",
    )
    return parser.parse_args()


def load_include_list(path: str | None) -> set[str] | None:
    if not path:
        return None
    include_path = Path(path).expanduser()
    selected: set[str] = set()
    for line in include_path.read_text(encoding="utf-8").splitlines():
        value = line.strip().lstrip("\ufeff")
        if not value or value.startswith("#"):
            continue
        selected.add(value.replace("\\", "/").lstrip("/"))
    return selected


def filter_records_by_include_list(
    records: list[FileRecord],
    include_paths: set[str] | None,
) -> tuple[list[FileRecord], set[str]]:
    if include_paths is None:
        return records, set()
    filtered: list[FileRecord] = []
    found: set[str] = set()
    for record in records:
        normalized = record.relative_path.replace("\\", "/")
        if normalized in include_paths:
            filtered.append(record)
            found.add(normalized)
    return filtered, include_paths - found


def process_file(record: FileRecord, use_ocr: bool, max_rows: int) -> FileProcessingOutcome:
    try:
        extraction = extract_text(record, use_ocr=use_ocr, max_rows=max_rows)
        if extraction.status == "skipped":
            return FileProcessingOutcome(
                stats_bucket="skipped",
                log_stage="text_extraction",
                log_status="skipped",
                log_message="; ".join(extraction.warnings),
            )
        if extraction.status == "error":
            return FileProcessingOutcome(
                stats_bucket="error",
                log_stage="text_extraction",
                log_status="error",
                log_message="; ".join(extraction.warnings),
            )

        pii_result = detect_pii(record, extraction.text, extraction.metadata)
        table_analysis = analyze_table_file(record, max_rows=max_rows)
        if table_analysis:
            pii_result.metadata["table_analysis"] = table_analysis
        doc_type = detect_document_type(record, extraction.text, extraction.metadata, pii_result)
        risk = classify_risk(record, extraction.text, extraction.metadata, pii_result, doc_type)

        return FileProcessingOutcome(
            stats_bucket="processed",
            log_stage="pipeline",
            log_status="ok",
            log_message=f"risk={risk.level}; score={risk.score}",
            extracted_text=extraction.text,
            pii_result=pii_result,
            document_type=doc_type,
            risk=risk,
        )
    except Exception as exc:
        return FileProcessingOutcome(
            stats_bucket="error",
            log_stage="pipeline",
            log_status="error",
            log_message=repr(exc),
        )


def report_rows_in_scan_order(report_rows_by_index: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    return [report_rows_by_index[index] for index in sorted(report_rows_by_index)]


def is_heavy_record(record: FileRecord) -> bool:
    return record.extension in HEAVY_PROCESS_EXTENSIONS


def split_by_processing_weight(
    records: list[tuple[int, FileRecord]],
) -> tuple[list[tuple[int, FileRecord]], list[tuple[int, FileRecord]]]:
    light_records: list[tuple[int, FileRecord]] = []
    heavy_records: list[tuple[int, FileRecord]] = []
    for item in records:
        _, record = item
        if is_heavy_record(record):
            heavy_records.append(item)
        else:
            light_records.append(item)
    return light_records, heavy_records


def split_heavy_records(
    records: list[tuple[int, FileRecord]],
) -> tuple[list[tuple[int, FileRecord]], list[tuple[int, FileRecord]]]:
    pdf_records: list[tuple[int, FileRecord]] = []
    other_heavy_records: list[tuple[int, FileRecord]] = []
    for item in records:
        _, record = item
        if record.extension in PDF_EXTENSIONS:
            pdf_records.append(item)
        else:
            other_heavy_records.append(item)
    return pdf_records, other_heavy_records


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


def apply_outcome(
    *,
    index: int,
    record: FileRecord,
    outcome: FileProcessingOutcome,
    dirs: OutputDirs,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
) -> bool:
    if outcome.stats_bucket == "processed":
        if (
            outcome.extracted_text is None
            or outcome.pii_result is None
            or outcome.risk is None
            or outcome.document_type is None
        ):
            stats.error_files += 1
            logger.write(record.path, "pipeline", "error", "processed outcome is missing required payload")
            return False
        try:
            text_path = write_extracted_text(dirs.extracted_texts, record, outcome.extracted_text)
            findings_path = write_pii_findings(dirs.pii_findings, record, outcome.pii_result)
        except Exception as exc:
            stats.error_files += 1
            logger.write(record.path, "output", "error", repr(exc))
            return False

        stats.processed_files += 1
        if outcome.risk.include_in_report:
            report_rows_by_index[index] = build_report_row(
                record,
                outcome.pii_result,
                outcome.risk,
                outcome.document_type,
                text_path,
                findings_path,
            )
    elif outcome.stats_bucket == "skipped":
        stats.skipped_files += 1
    else:
        stats.error_files += 1

    logger.write(record.path, outcome.log_stage, outcome.log_status, outcome.log_message)
    return outcome.stats_bucket == "processed" and bool(outcome.risk and outcome.risk.include_in_report)


def apply_outcome_and_flush(
    *,
    index: int,
    record: FileRecord,
    outcome: FileProcessingOutcome,
    dirs: OutputDirs,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
    handled_files: int,
) -> int:
    handled_files += 1
    should_flush_report = apply_outcome(
        index=index,
        record=record,
        outcome=outcome,
        dirs=dirs,
        logger=logger,
        stats=stats,
        report_rows_by_index=report_rows_by_index,
    )
    if should_flush_report or handled_files % REPORT_FLUSH_EVERY_FILES == 0:
        write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)
    return handled_files


def describe_record(record: FileRecord) -> str:
    return f"{record.relative_path} ({record.extension or 'no extension'}, {record.size_bytes / 1024 / 1024:.1f} MB)"


def print_progress(message: str) -> None:
    print(message, flush=True)


def process_file_worker(
    record: FileRecord,
    use_ocr: bool,
    max_rows: int,
    result_queue: mp.Queue,
) -> None:
    result_queue.put(process_file(record, use_ocr=use_ocr, max_rows=max_rows))


def process_file_in_isolated_process(
    record: FileRecord,
    use_ocr: bool,
    max_rows: int,
    timeout_seconds: int,
) -> FileProcessingOutcome:
    if timeout_seconds <= 0:
        return process_file(record, use_ocr=use_ocr, max_rows=max_rows)

    process: mp.Process | None = None
    try:
        context = mp.get_context("spawn")
        result_queue = context.Queue(maxsize=1)
        process = context.Process(
            target=process_file_worker,
            args=(record, use_ocr, max_rows, result_queue),
        )
        process.start()
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                outcome = result_queue.get(timeout=0.2)
                process.join(5)
                return outcome
            except queue.Empty:
                if not process.is_alive():
                    process.join()
                    return FileProcessingOutcome(
                        stats_bucket="error",
                        log_stage="pipeline",
                        log_status="error",
                        log_message=f"isolated process exited without result; exit_code={process.exitcode}",
                    )
                if time.monotonic() < deadline:
                    continue

            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()
            return FileProcessingOutcome(
                stats_bucket="error",
                log_stage="pipeline",
                log_status="error",
                log_message=f"file processing timed out after {timeout_seconds}s",
            )
    except (OSError, PermissionError):
        return process_file(record, use_ocr=use_ocr, max_rows=max_rows)
    except KeyboardInterrupt:
        if process is not None and process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()
        raise
    except Exception as exc:
        return FileProcessingOutcome(
            stats_bucket="error",
            log_stage="pipeline",
            log_status="error",
            log_message=repr(exc),
        )


def process_file_in_one_process_pool(record: FileRecord, use_ocr: bool, max_rows: int) -> FileProcessingOutcome:
    try:
        with ProcessPoolExecutor(max_workers=1) as executor:
            future = executor.submit(process_file, record, use_ocr, max_rows)
            return future.result()
    except (OSError, PermissionError):
        return process_file(record, use_ocr=use_ocr, max_rows=max_rows)
    except BrokenProcessPool as exc:
        return FileProcessingOutcome(
            stats_bucket="error",
            log_stage="pipeline",
            log_status="error",
            log_message=f"isolated process failed: {exc!r}",
        )
    except Exception as exc:
        return FileProcessingOutcome(
            stats_bucket="error",
            log_stage="pipeline",
            log_status="error",
            log_message=repr(exc),
        )


def process_records_sequentially(
    *,
    records: list[tuple[int, FileRecord]],
    dirs: OutputDirs,
    use_ocr: bool,
    max_rows: int,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
    handled_files: int,
) -> int:
    total = len(records)
    for offset, (index, record) in enumerate(records, start=1):
        print_progress(f"[{offset}/{total}] Processing {describe_record(record)}")
        outcome = process_file(record, use_ocr=use_ocr, max_rows=max_rows)
        handled_files = apply_outcome_and_flush(
            index=index,
            record=record,
            outcome=outcome,
            dirs=dirs,
            logger=logger,
            stats=stats,
            report_rows_by_index=report_rows_by_index,
            handled_files=handled_files,
        )
    return handled_files


def process_records_isolated(
    *,
    records: list[tuple[int, FileRecord]],
    dirs: OutputDirs,
    use_ocr: bool,
    max_rows: int,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
    handled_files: int,
    timeout_seconds: int,
    progress_label: str,
) -> int:
    total = len(records)
    for offset, (index, record) in enumerate(records, start=1):
        print_progress(f"[{offset}/{total}] Processing {progress_label} {describe_record(record)}")
        outcome = process_file_in_isolated_process(
            record,
            use_ocr=use_ocr,
            max_rows=max_rows,
            timeout_seconds=timeout_seconds,
        )
        handled_files = apply_outcome_and_flush(
            index=index,
            record=record,
            outcome=outcome,
            dirs=dirs,
            logger=logger,
            stats=stats,
            report_rows_by_index=report_rows_by_index,
            handled_files=handled_files,
        )
    return handled_files


def terminate_process(process: mp.Process) -> None:
    if not process.is_alive():
        return
    process.terminate()
    process.join(5)
    if process.is_alive():
        process.kill()
        process.join()


def build_timeout_outcome(timeout_seconds: int) -> FileProcessingOutcome:
    return FileProcessingOutcome(
        stats_bucket="error",
        log_stage="pipeline",
        log_status="error",
        log_message=f"file processing timed out after {timeout_seconds}s",
    )


def build_empty_process_outcome(exit_code: int | None) -> FileProcessingOutcome:
    return FileProcessingOutcome(
        stats_bucket="error",
        log_stage="pipeline",
        log_status="error",
        log_message=f"isolated process exited without result; exit_code={exit_code}",
    )


def process_records_isolated_parallel(
    *,
    records: list[tuple[int, FileRecord]],
    max_parallel: int,
    dirs: OutputDirs,
    use_ocr: bool,
    max_rows: int,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
    handled_files: int,
    timeout_seconds: int,
    progress_label: str,
) -> int:
    if not records:
        return handled_files
    if max_parallel <= 1 or len(records) <= 1:
        return process_records_isolated(
            records=records,
            dirs=dirs,
            use_ocr=use_ocr,
            max_rows=max_rows,
            logger=logger,
            stats=stats,
            report_rows_by_index=report_rows_by_index,
            handled_files=handled_files,
            timeout_seconds=timeout_seconds,
            progress_label=progress_label,
        )

    total = len(records)
    pending = records[:]
    active: list[ActiveIsolatedTask] = []
    started = 0
    finished = 0

    try:
        context = mp.get_context("spawn")
        while pending or active:
            while pending and len(active) < max_parallel:
                index, record = pending.pop(0)
                result_queue = context.Queue(maxsize=1)
                process = context.Process(
                    target=process_file_worker,
                    args=(record, use_ocr, max_rows, result_queue),
                )
                process.start()
                started += 1
                deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else None
                active.append(ActiveIsolatedTask(index, record, process, result_queue, deadline))
                print_progress(
                    f"[{started}/{total}] Started {progress_label} {describe_record(record)} "
                    f"({len(active)}/{max_parallel} active)"
                )

            made_progress = False
            for task in active[:]:
                outcome: FileProcessingOutcome | None = None
                try:
                    outcome = task.result_queue.get_nowait()
                    task.process.join(5)
                except queue.Empty:
                    if not task.process.is_alive():
                        task.process.join()
                        outcome = build_empty_process_outcome(task.process.exitcode)
                    elif task.deadline is not None and time.monotonic() >= task.deadline:
                        terminate_process(task.process)
                        outcome = build_timeout_outcome(timeout_seconds)

                if outcome is None:
                    continue

                active.remove(task)
                finished += 1
                made_progress = True
                print_progress(f"[{finished}/{total}] Finished {progress_label} {describe_record(task.record)}")
                handled_files = apply_outcome_and_flush(
                    index=task.index,
                    record=task.record,
                    outcome=outcome,
                    dirs=dirs,
                    logger=logger,
                    stats=stats,
                    report_rows_by_index=report_rows_by_index,
                    handled_files=handled_files,
                )

            if not made_progress:
                time.sleep(0.2)
    except (OSError, PermissionError) as exc:
        logger.write(
            records[0][1].path,
            "pipeline",
            "retry",
            f"{progress_label} parallel processing unavailable; retrying one-by-one: {exc!r}",
        )
        return process_records_isolated(
            records=records,
            dirs=dirs,
            use_ocr=use_ocr,
            max_rows=max_rows,
            logger=logger,
            stats=stats,
            report_rows_by_index=report_rows_by_index,
            handled_files=handled_files,
            timeout_seconds=timeout_seconds,
            progress_label=f"{progress_label} retry",
        )
    except KeyboardInterrupt:
        print_progress(f"Interrupted. Stopping {len(active)} active {progress_label} processes...")
        for task in active:
            terminate_process(task.process)
        raise

    return handled_files


def process_records_in_pool(
    *,
    records: list[tuple[int, FileRecord]],
    pool_name: str,
    max_workers: int,
    dirs: OutputDirs,
    use_ocr: bool,
    max_rows: int,
    logger: JsonlLogger,
    stats: ProcessingStats,
    report_rows_by_index: dict[int, dict[str, Any]],
    handled_files: int,
    timeout_seconds: int,
) -> int:
    if not records:
        return handled_files
    if max_workers <= 1 or len(records) <= 1:
        return process_records_isolated(
            records=records,
            dirs=dirs,
            use_ocr=use_ocr,
            max_rows=max_rows,
            logger=logger,
            stats=stats,
            report_rows_by_index=report_rows_by_index,
            handled_files=handled_files,
            timeout_seconds=timeout_seconds,
            progress_label=pool_name,
        )

    completed_indexes: set[int] = set()
    retry_records: list[tuple[int, FileRecord]] = []
    worker_count = min(max_workers, len(records))
    print_progress(f"Processing {len(records)} {pool_name} records with {worker_count} workers")
    executor: ProcessPoolExecutor | None = None
    try:
        executor = ProcessPoolExecutor(max_workers=worker_count)
        futures = {
            executor.submit(process_file, record, use_ocr, max_rows): (index, record)
            for index, record in records
        }
        for future in as_completed(futures):
            index, record = futures[future]
            if index in completed_indexes:
                continue
            try:
                outcome = future.result()
            except BrokenProcessPool as exc:
                logger.write(
                    record.path,
                    "pipeline",
                    "retry",
                    f"{pool_name} process pool failed; retrying unfinished files one-by-one: {exc!r}",
                )
                retry_records = [
                    item
                    for item in records
                    if item[0] not in completed_indexes
                ]
                for pending_future in futures:
                    pending_future.cancel()
                break
            except Exception as exc:
                outcome = FileProcessingOutcome(
                    stats_bucket="error",
                    log_stage="pipeline",
                    log_status="error",
                    log_message=repr(exc),
                )
            completed_indexes.add(index)
            print_progress(f"[{len(completed_indexes)}/{len(records)}] Finished {describe_record(record)}")
            handled_files = apply_outcome_and_flush(
                index=index,
                record=record,
                outcome=outcome,
                dirs=dirs,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
            )
    except (OSError, PermissionError) as exc:
        logger.write(
            records[0][1].path,
            "pipeline",
            "retry",
            f"{pool_name} process pool unavailable; processing in current process: {exc!r}",
        )
        retry_records = [
            item
            for item in records
            if item[0] not in completed_indexes
        ]
    except KeyboardInterrupt:
        print_progress("Interrupted. Stopping worker processes...")
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

    if retry_records:
        handled_files = process_records_isolated(
            records=retry_records,
            dirs=dirs,
            use_ocr=use_ocr,
            max_rows=max_rows,
            logger=logger,
            stats=stats,
            report_rows_by_index=report_rows_by_index,
            handled_files=handled_files,
            timeout_seconds=timeout_seconds,
            progress_label=f"{pool_name} retry",
        )
    return handled_files


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    workers = max(1, args.workers)
    file_timeout = max(0, args.file_timeout)
    pdf_workers = max(1, args.pdf_workers)

    if not input_dir.exists() or not input_dir.is_dir():
        print(f"Input directory does not exist or is not a directory: {input_dir}", file=sys.stderr)
        return 2

    dirs = ensure_output_dirs(output_dir)
    logger = JsonlLogger(dirs.logs / "processing_log.jsonl")
    stats = ProcessingStats()
    report_rows_by_index: dict[int, dict[str, Any]] = {}

    include_paths = load_include_list(args.include_list)
    records = scan_files(input_dir, args.max_file_size_mb)
    records, missing_include_paths = filter_records_by_include_list(records, include_paths)
    stats.total_files = len(records) + len(missing_include_paths)
    for missing_path in sorted(missing_include_paths):
        stats.skipped_files += 1
        logger.write(input_dir / missing_path, "scan", "skipped", "Path from include list was not found")
    write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)

    try:
        pending_records: list[tuple[int, FileRecord]] = []
        handled_files = 0
        for index, record in enumerate(records):
            if record.status == "skipped":
                handled_files += 1
                stats.skipped_files += 1
                logger.write(record.path, "scan", "skipped", record.error or "Skipped by scanner")
                if handled_files % REPORT_FLUSH_EVERY_FILES == 0:
                    write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)
            else:
                pending_records.append((index, record))

        light_records, heavy_records = split_by_processing_weight(pending_records)
        pdf_records, other_heavy_records = split_heavy_records(heavy_records)
        print_progress(
            f"Found {len(records)} files: {len(light_records)} light, {len(heavy_records)} heavy, "
            f"{stats.skipped_files} skipped by scanner"
        )
        if pdf_records:
            print_progress(f"PDF parallelism: {min(pdf_workers, len(pdf_records))} workers for {len(pdf_records)} PDFs")

        if workers == 1:
            handled_files = process_records_sequentially(
                records=light_records,
                dirs=dirs,
                use_ocr=args.ocr,
                max_rows=args.max_rows,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
            )
            handled_files = process_records_isolated_parallel(
                records=pdf_records,
                max_parallel=pdf_workers,
                dirs=dirs,
                use_ocr=args.ocr,
                max_rows=args.max_rows,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
                timeout_seconds=file_timeout,
                progress_label="PDF",
            )
            handled_files = process_records_isolated(
                records=other_heavy_records,
                dirs=dirs,
                use_ocr=args.ocr,
                max_rows=args.max_rows,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
                timeout_seconds=file_timeout,
                progress_label="heavy file",
            )
        else:
            handled_files = process_records_in_pool(
                records=light_records,
                pool_name="light-file",
                max_workers=workers,
                dirs=dirs,
                use_ocr=args.ocr,
                max_rows=args.max_rows,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
                timeout_seconds=file_timeout,
            )
            handled_files = process_records_isolated_parallel(
                records=pdf_records,
                max_parallel=pdf_workers,
                dirs=dirs,
                use_ocr=args.ocr,
                max_rows=args.max_rows,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
                timeout_seconds=file_timeout,
                progress_label="PDF",
            )
            handled_files = process_records_isolated(
                records=other_heavy_records,
                dirs=dirs,
                use_ocr=args.ocr,
                max_rows=args.max_rows,
                logger=logger,
                stats=stats,
                report_rows_by_index=report_rows_by_index,
                handled_files=handled_files,
                timeout_seconds=file_timeout,
                progress_label="heavy file",
            )
    except KeyboardInterrupt:
        print_progress("Interrupted by user. Partial reports were saved.")
        return 130
    finally:
        write_reports(dirs.reports, report_rows_in_scan_order(report_rows_by_index), stats)

    print(f"Done. Processed: {stats.processed_files}; skipped: {stats.skipped_files}; errors: {stats.error_files}")
    print(f"Reports: {dirs.reports}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

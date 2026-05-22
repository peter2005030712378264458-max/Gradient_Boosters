from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from src.models import ExtractionResult, FileRecord
from src.utils.text import normalize_text, truncate_text


DEFAULT_FRAME_INTERVAL_SECONDS = 0.5
DEFAULT_MAX_FRAMES = 8
MAX_TEXT_SNIPPETS = 5
VIDEO_OCR_LANGUAGES = ("rus+eng", "eng")
VIDEO_OCR_CONFIGS = ("--oem 3 --psm 6",)
MAX_OCR_FRAMES = 4
MAX_FRAME_CANDIDATES = 6

ImageEnhance = None
ImageFilter = None
ImageOps = None


def extract_video(record: FileRecord, use_ocr: bool) -> ExtractionResult:
    metadata = {
        "extractor": "video",
        "ocr_used": False,
        "frame_interval_seconds": DEFAULT_FRAME_INTERVAL_SECONDS,
        "max_frames": DEFAULT_MAX_FRAMES,
    }
    if not use_ocr:
        return ExtractionResult("", "ok", metadata=metadata, warnings=["Video OCR disabled"])

    if shutil.which("ffmpeg") is None:
        return ExtractionResult("", "ok", metadata=metadata, warnings=["ffmpeg unavailable for video frame extraction"])

    try:
        global ImageEnhance, ImageFilter, ImageOps
        from PIL import Image
        from PIL import ImageEnhance as pil_image_enhance
        from PIL import ImageFilter as pil_image_filter
        from PIL import ImageOps as pil_image_ops
        import pytesseract
    except Exception as exc:
        return ExtractionResult("", "ok", metadata=metadata, warnings=[f"OCR unavailable: {exc.__class__.__name__}"])
    ImageEnhance = pil_image_enhance
    ImageFilter = pil_image_filter
    ImageOps = pil_image_ops

    warnings: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="video_ocr_") as temp_dir:
            frame_dir = Path(temp_dir)
            frame_paths, ffmpeg_warnings = extract_video_frames(record.path, frame_dir)
            warnings.extend(ffmpeg_warnings)

            metadata["frames_extracted"] = len(frame_paths)
            if not frame_paths:
                return ExtractionResult("", "ok", metadata=metadata, warnings=warnings + ["No video frames extracted"])

            ocr_frame_paths = select_ocr_frame_paths(Image, frame_paths)
            metadata["frames_ocr_attempted"] = len(ocr_frame_paths)

            candidates: list[tuple[int, int, str, str, str]] = []
            for frame_path in ocr_frame_paths:
                with Image.open(frame_path) as image:
                    frame_candidates = ocr_video_frame(pytesseract, image)
                for score, language, variant, text in frame_candidates:
                    if score > 0 and text.strip():
                        frame_number = int(frame_path.stem.rsplit("_", 1)[-1])
                        candidates.append((score, frame_number, language, variant, text.strip()))

            metadata["ocr_used"] = True
            metadata["ocr_languages"] = sorted({language for _, _, language, _, _ in candidates})
            metadata["ocr_candidate_count"] = len(candidates)

            snippets = select_best_text_snippets(candidates)
            return ExtractionResult(truncate_text(normalize_text("\n\n".join(snippets))), "ok", metadata=metadata, warnings=warnings)
    except Exception as exc:
        return ExtractionResult("", "ok", metadata=metadata, warnings=[f"Video OCR failed: {exc}"])


def extract_video_frames(video_path: Path, frame_dir: Path) -> tuple[list[Path], list[str]]:
    duration = probe_video_duration(video_path)
    frame_count = DEFAULT_MAX_FRAMES
    if duration and duration > 0:
        frame_count = min(DEFAULT_MAX_FRAMES, max(1, int(duration / DEFAULT_FRAME_INTERVAL_SECONDS)))
    timestamps = build_frame_timestamps(duration, frame_count)
    warnings: list[str] = []
    frame_paths: list[Path] = []

    for index, timestamp in enumerate(timestamps, start=1):
        frame_path = frame_dir / f"frame_{index:04d}.png"
        command = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-ss",
            f"{timestamp:.3f}",
            "-i",
            str(video_path),
            "-frames:v",
            "1",
            "-vf",
            "scale=2600:-2:force_original_aspect_ratio=decrease",
            str(frame_path),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode == 0 and frame_path.exists():
            frame_paths.append(frame_path)
            continue
        message = completed.stderr.strip() or completed.stdout.strip() or f"ffmpeg exited with {completed.returncode}"
        warnings.append(f"frame {index}: {message}")

    return frame_paths, warnings


def probe_video_duration(video_path: Path) -> float | None:
    if shutil.which("ffprobe") is None:
        return None
    completed = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(video_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    try:
        return float(completed.stdout.strip())
    except ValueError:
        return None


def build_frame_timestamps(duration: float | None, frame_count: int) -> list[float]:
    if frame_count <= 1:
        return [0.0]
    if not duration or duration <= 0:
        return [index * DEFAULT_FRAME_INTERVAL_SECONDS for index in range(frame_count)]
    # Avoid the very last frame because some containers seek past EOF there.
    end = max(duration - 0.1, 0.0)
    step = end / max(frame_count - 1, 1)
    return [index * step for index in range(frame_count)]


def select_ocr_frame_paths(image_module, frame_paths: list[Path]) -> list[Path]:
    if len(frame_paths) <= MAX_OCR_FRAMES:
        return frame_paths

    scored_paths: list[tuple[float, int, Path]] = []
    for index, frame_path in enumerate(frame_paths):
        try:
            with image_module.open(frame_path) as image:
                score = score_frame_for_ocr(image)
        except Exception:
            score = 0.0
        scored_paths.append((score, index, frame_path))

    selected = sorted(scored_paths, key=lambda item: item[0], reverse=True)[:MAX_OCR_FRAMES]
    selected.sort(key=lambda item: item[1])
    return [frame_path for _, _, frame_path in selected]


def score_frame_for_ocr(image) -> float:
    gray = ImageOps.grayscale(image.convert("RGB"))
    width, height = gray.size
    focus = gray.crop((0, int(height * 0.18), width, int(height * 0.88)))
    thumb_width = 260
    thumb_height = max(1, int(focus.height * thumb_width / max(focus.width, 1)))
    thumb = focus.resize((thumb_width, thumb_height))

    try:
        import cv2
        import numpy as np

        array = np.array(thumb)
        edges = cv2.Canny(array, 45, 140)
        edge_density = float(np.count_nonzero(edges)) / max(edges.size, 1)
        contrast = float(array.std()) / 255.0
        mid_brightness = float(((array > 105) & (array < 245)).sum()) / max(array.size, 1)
        return edge_density * 4.0 + contrast + mid_brightness
    except Exception:
        edges = thumb.filter(ImageFilter.FIND_EDGES)
        histogram = edges.histogram()
        edge_pixels = sum(count for value, count in enumerate(histogram) if value > 40)
        return edge_pixels / max(thumb.width * thumb.height, 1)


def ocr_video_frame(pytesseract_module, image) -> list[tuple[int, str, str, str]]:
    candidates: list[tuple[int, str, str, str]] = []
    for region_name, region in video_ocr_regions(image):
        for variant_name, variant in video_ocr_variants(region):
            for language in VIDEO_OCR_LANGUAGES:
                for config in VIDEO_OCR_CONFIGS:
                    try:
                        text = pytesseract_module.image_to_string(variant, lang=language, config=config)
                    except Exception:
                        continue
                    score = score_ocr_text(text)
                    candidates.append((score, language, f"{region_name}/{variant_name} {config}", text))
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[:MAX_FRAME_CANDIDATES]


def video_ocr_regions(image) -> list[tuple[str, object]]:
    rgb = image.convert("RGB")
    width, height = rgb.size
    boxes: list[tuple[str, tuple[int, int, int, int]]] = [("full", (0, 0, width, height))]

    if height >= width:
        boxes.extend(
            [
                ("middle_band", (0, int(height * 0.22), width, int(height * 0.78))),
                ("document_band", (0, int(height * 0.30), width, int(height * 0.72))),
                ("lower_band", (0, int(height * 0.32), width, int(height * 0.85))),
            ]
        )
    else:
        boxes.extend(
            [
                ("center_band", (int(width * 0.08), 0, int(width * 0.92), height)),
                ("middle_strip", (int(width * 0.10), int(height * 0.12), int(width * 0.90), int(height * 0.88))),
                ("lower_strip", (int(width * 0.08), int(height * 0.30), int(width * 0.92), height)),
            ]
        )

    boxes.extend(detect_document_region_boxes(rgb))

    regions: list[tuple[str, object]] = []
    seen: set[tuple[int, int, int, int]] = set()
    for name, box in boxes:
        x0, y0, x1, y1 = clamp_box(box, width, height)
        if x1 - x0 < 80 or y1 - y0 < 80:
            continue
        normalized_box = (x0, y0, x1, y1)
        if normalized_box in seen:
            continue
        seen.add(normalized_box)
        regions.append((name, rgb.crop(normalized_box)))
    return regions


def detect_document_region_boxes(image) -> list[tuple[str, tuple[int, int, int, int]]]:
    try:
        import cv2
        import numpy as np
    except Exception:
        return []

    array = np.array(image)
    height, width = array.shape[:2]
    hsv = cv2.cvtColor(array, cv2.COLOR_RGB2HSV)
    saturation = hsv[:, :, 1]
    value = hsv[:, :, 2]

    masks = [
        ((value > 110) & (saturation < 90)).astype("uint8") * 255,
        ((value > 135) & (saturation < 150)).astype("uint8") * 255,
    ]

    found: list[tuple[float, tuple[int, int, int, int]]] = []
    kernel_size = max(15, min(width, height) // 35)
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (kernel_size, kernel_size))
    for mask in masks:
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel, iterations=2)
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel, iterations=1)
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)
            area_ratio = (w * h) / (width * height)
            aspect_ratio = w / h if h else 0
            if not 0.08 <= area_ratio <= 0.65:
                continue
            if not 0.8 <= aspect_ratio <= 4.2:
                continue
            padding = int(max(w, h) * 0.08)
            found.append((area_ratio, (x - padding, y - padding, x + w + padding, y + h + padding)))

    found.sort(key=lambda item: item[0], reverse=True)
    return [(f"detected_document_{index}", box) for index, (_, box) in enumerate(found[:1], start=1)]


def clamp_box(box: tuple[int, int, int, int], width: int, height: int) -> tuple[int, int, int, int]:
    x0, y0, x1, y1 = box
    return max(0, x0), max(0, y0), min(width, x1), min(height, y1)


def resize_for_ocr(image):
    width, height = image.size
    if width >= 1800:
        return image
    scale = min(2.5, 1800 / max(width, 1))
    return image.resize((int(width * scale), int(height * scale)))


def video_ocr_variants(image) -> list[tuple[str, object]]:
    resized = resize_for_ocr(image.convert("RGB"))
    gray = ImageOps.grayscale(resized)
    enhanced = ImageEnhance.Contrast(gray).enhance(2.0)
    enhanced = ImageEnhance.Sharpness(enhanced).enhance(2.0)
    return [("enhanced_gray", enhanced)]


def score_ocr_text(text: str) -> int:
    stripped = text.strip()
    if len(stripped) < 12:
        return 0
    words = [word for word in stripped.replace("\n", " ").split() if sum(ch.isalpha() for ch in word) >= 3]
    alnum_count = sum(ch.isalnum() for ch in stripped)
    digit_count = sum(ch.isdigit() for ch in stripped)
    symbol_count = sum(not ch.isalnum() and not ch.isspace() for ch in stripped)
    newline_count = stripped.count("\n")
    return (len(words) * 12) + (digit_count * 2) + alnum_count + newline_count - (symbol_count * 3)


def select_best_text_snippets(candidates: list[tuple[int, int, str, str, str]]) -> list[str]:
    selected: list[tuple[int, str]] = []
    seen_fingerprints: set[str] = set()
    seen_frame_regions: set[tuple[int, str]] = set()
    best_score = max((score for score, *_ in candidates), default=0)
    min_score = max(35, int(best_score * 0.45))
    for score, frame_number, language, variant, text in sorted(candidates, key=lambda item: item[0], reverse=True):
        if score < min_score:
            continue
        region = variant.split(" ", 1)[0]
        frame_region = (frame_number, region)
        if frame_region in seen_frame_regions:
            continue
        fingerprint = fingerprint_text(text)
        if not fingerprint or fingerprint in seen_fingerprints:
            continue
        seen_frame_regions.add(frame_region)
        seen_fingerprints.add(fingerprint)
        selected.append((frame_number, f"[frame_{frame_number:04d}; {language}; {variant}; score={score}]\n{text}"))
        if len(selected) >= MAX_TEXT_SNIPPETS:
            break
    selected.sort(key=lambda item: item[0])
    return [text for _, text in selected]


def fingerprint_text(text: str) -> str:
    normalized = "".join(ch.lower() for ch in text if ch.isalnum())
    if len(normalized) < 20:
        return ""
    return normalized[:120]

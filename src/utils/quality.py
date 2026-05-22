from __future__ import annotations

import re


GARBLED_OCR_MARKERS = (
    "3a",
    "bme",
    "co6",
    "ctom",
    "moct",
    "opra",
    "pa3",
    "py6",
    "meponp",
    "nepe",
    "npe",
    "npo",
    "onn",
    "komh",
    "tpa",
    "bkn",
    "mnho",
    "hpиka",
    "hphka",
    "pocch",
    "tocyi",
    "tocuh",
    "o6pa",
    "yhh",
    "mhh",
    "xehe",
    "ctoh",
    "npen",
    "cyji",
)


PDF_LIGATURE_LOSS_PATTERNS = (
    r"\breect(?:s|ed|ing)?\b",
    r"\beect(?:s|ed|ive|ively)?\b",
    r"\bdene[sd]?\b",
    r"\bdening\b",
    r"\bdenition(?:s)?\b",
    r"\bnd(?:s|ing)?\b",
    r"\bspecic(?:ally)?\b",
    r"\barticial(?:ly)?\b",
    r"\bidentier(?:s)?\b",
    r"\baliate(?:s|d)?\b",
    r"\bprole(?:s)?\b",
    r"\bverication\b",
    r"\bconrm(?:s|ed|ing)?\b",
    r"\bcongure(?:s|d|ing)?\b",
)


def has_lost_pdf_ligatures(text: str) -> bool:
    """Detect English PDF text where fi/fl ligatures were dropped by an extractor."""
    sample = text[:20_000]
    letters = re.findall(r"[A-Za-zА-Яа-яЁё]", sample)
    if len(letters) < 500:
        return False

    latin_ratio = len(re.findall(r"[A-Za-z]", sample)) / max(len(letters), 1)
    if latin_ratio < 0.75:
        return False

    lower = sample.lower()
    hits = sum(len(re.findall(pattern, lower)) for pattern in PDF_LIGATURE_LOSS_PATTERNS)
    return hits >= 3


def is_probably_garbled_ocr(text: str, source_name: str = "") -> bool:
    """Detect OCR output that is too corrupted to use for PII/risk analysis.

    This is intentionally conservative. It targets the common failure mode where
    Russian scans are recognized as a Latin/Cyrillic mixture such as
    "MNHOEPHAYKИPOCCHH" instead of readable Russian.
    """
    sample = text[:5000]
    letters = re.findall(r"[A-Za-zА-Яа-яЁё]", sample)
    if len(letters) < 200:
        return False

    cyrillic = re.findall(r"[А-Яа-яЁё]", sample)
    latin = re.findall(r"[A-Za-z]", sample)
    cyrillic_ratio = len(cyrillic) / max(len(letters), 1)
    latin_ratio = len(latin) / max(len(letters), 1)

    lower = sample.lower()
    marker_hits = sum(lower.count(marker) for marker in GARBLED_OCR_MARKERS)
    has_russian_hint = any(word in lower for word in ("приказ", "договор", "паспорт", "персональн", "россии"))

    mixed_tokens = 0
    digit_letter_tokens = 0
    for token in re.findall(r"[A-Za-zА-Яа-яЁё0-9]{5,}", sample):
        has_latin = bool(re.search(r"[A-Za-z]", token))
        has_cyrillic = bool(re.search(r"[А-Яа-яЁё]", token))
        has_digit = bool(re.search(r"\d", token))
        if has_digit and has_latin:
            digit_letter_tokens += 1
        if (has_latin and has_cyrillic) or (has_digit and (has_latin or has_cyrillic)):
            mixed_tokens += 1

    if marker_hits >= 3:
        return True
    if latin_ratio > 0.85 and cyrillic_ratio < 0.08 and marker_hits >= 2 and digit_letter_tokens >= 3:
        return True
    if latin_ratio > 0.92 and cyrillic_ratio < 0.05 and marker_hits >= 4:
        return True
    if has_russian_hint and latin_ratio > 0.45 and cyrillic_ratio < 0.45:
        return True
    return has_russian_hint and mixed_tokens >= 20 and latin_ratio > 0.35

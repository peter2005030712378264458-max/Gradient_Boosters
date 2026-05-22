from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Iterable

from src.models import CategoryFinding, FileRecord, PIIResult
from src.pii_detection.dictionaries import KEYWORDS
from src.pii_detection.name_filters import filter_full_name_matches
from src.pii_detection.patterns import BIRTH_DATE_CONTEXT_PATTERNS, PASSPORT_CONTEXT_PATTERNS, PATTERNS
from src.pii_detection.validators import luhn_check, validate_inn, validate_snils


DIRECT_IDENTIFIER_CATEGORIES = {"passport_rf", "foreign_id_document", "snils", "inn_person", "driver_license", "mrz"}
LEGAL_ENTITY_CATEGORIES = {"inn_legal", "bik", "bank_account"}
FINANCIAL_CATEGORIES = {"bank_card", "bank_account", "bik", "cvv"}
CONTACT_CATEGORIES = {"phone", "email", "address"}
DEMOGRAPHIC_CATEGORIES = {"birth_date", "birth_place", "nationality", "race"}
SPECIAL_CATEGORY_CATEGORIES = {"health", "religion", "political_views", "biometric"}
WEAK_KEYWORD_CATEGORIES = {"address", "birth_place", "health", "religion", "political_views", "nationality", "race", "biometric"}


def detect_pii(record: FileRecord, text: str, extraction_metadata: dict) -> PIIResult:
    result = PIIResult(
        file_path=str(record.path),
        relative_path=record.relative_path,
        file_format=record.extension,
        metadata={"extraction": extraction_metadata},
    )
    haystack = text or ""
    path_text = f"{record.relative_path} {record.path.name}"
    unique_full_names: set[str] = set()

    for category, pattern in PATTERNS.items():
        if category == "passport_rf":
            candidates = list(pattern.finditer(haystack))
            matches = filter_generic_passport_matches(haystack, candidates)
            add_validation_stats(result, "passport_rf_generic", len(candidates), len(matches))
            add_matches(result, category, matches)
            continue

        pattern_matches = list(pattern.finditer(haystack))
        matches = [match.group(0) for match in pattern_matches]
        if category == "bank_card":
            matches = [
                match.group(0)
                for match in pattern_matches
                if luhn_check(match.group(0)) and is_plausible_bank_card_match(haystack, match)
            ]
        elif category == "snils":
            valid = [
                match.group(0)
                for match in pattern_matches
                if validate_snils(match.group(0)) and is_plausible_snils_match(haystack, match)
            ]
            add_validation_stats(result, "snils", len(matches), len(valid))
            matches = valid
        elif category == "inn":
            valid = [item for item in matches if validate_inn(item)]
            add_validation_stats(result, "inn", len(matches), len(valid))
            inn_person = [item for item in valid if len(re.sub(r"\D+", "", item)) == 12]
            inn_legal = [item for item in valid if len(re.sub(r"\D+", "", item)) == 10]
            add_matches(result, "inn_person", inn_person)
            add_matches(result, "inn_legal", inn_legal)
            continue
        elif category == "full_name":
            matches = filter_full_name_matches(matches)
            unique_full_names.update(normalize_person_name(item) for item in matches)
        add_matches(result, category, matches)

    passport_matches = find_contextual_passports(haystack)
    if passport_matches:
        add_matches(result, "passport_rf", passport_matches)
        result.metadata["passport_context_detected"] = True

    birth_date_matches = find_contextual_birth_dates(haystack)
    if birth_date_matches:
        add_matches(result, "birth_date", birth_date_matches)

    foreign_id_document_matches = find_foreign_identity_documents(haystack)
    if foreign_id_document_matches:
        add_matches(result, "foreign_id_document", foreign_id_document_matches)
        result.metadata["foreign_identity_document_detected"] = True

    lower_text = haystack.lower()
    lower_path = path_text.lower()
    for category, keywords in KEYWORDS.items():
        if category == "driver_license" and not has_driver_license_value_context(haystack):
            continue
        count = 0
        samples = []
        for keyword in keywords:
            occurrences = lower_text.count(keyword.lower()) + lower_path.count(keyword.lower())
            if occurrences:
                count += occurrences
                samples.append(keyword)
        if count:
            add_matches(result, category, samples, count_override=count)

    result.features = build_pii_features(record, result, haystack, unique_full_names)
    return result


def filter_generic_passport_matches(text: str, candidates: list[re.Match[str]]) -> list[str]:
    """Keep only low-ambiguity passport-looking numbers without touching other PII logic.

    A bare 10-digit sequence is too noisy: it often appears as a legal-entity INN,
    URL-encoded payload, UUID/Oid fragment, cache key, or another technical id.
    Contextual passport patterns below still catch compact numbers near words such
    as "паспорт", "серия", "номер", or "выдан".
    """
    matches: list[str] = []
    for match in candidates:
        value = match.group(0)
        if validate_inn(value):
            continue
        if not looks_like_human_passport_notation(value):
            continue
        if has_technical_identifier_context(text, match.start(), match.end()):
            continue
        if has_non_passport_number_context(text, match.start(), match.end()):
            continue
        if not has_passport_context_for_number(text, match.start(), match.end()):
            continue
        matches.append(value)
    return matches


def looks_like_human_passport_notation(value: str) -> bool:
    normalized = re.sub(r"\s+", " ", value.strip())
    return bool(re.fullmatch(r"\d{4} \d{6}|\d{2} \d{2} \d{6}", normalized))


def has_technical_identifier_context(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 40) : min(len(text), end + 40)]
    lower_window = window.lower()
    if re.search(r"%[0-9a-f]{2}", lower_window):
        return True
    if re.search(r"[0-9a-f]{4,}-[0-9a-f-]{4,}", lower_window):
        return True
    if re.search(r"\b(?:id|oid|uuid|guid|token|hash|session|objectid)\b", lower_window):
        return True
    return False


def has_non_passport_number_context(text: str, start: int, end: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].lower()
    legal_or_financial_marker = re.search(
        r"\b(?:инн|кпп|огрн|окпо|октмо|окато|бик|уин|кбк|снилс|екс|уфк)\b|"
        r"\b(?:банк\s+получателя|р/с|к/с|расч[её]тн(?:ый|ого)\s+счет|л\.?сч\.?|лицев(?:ой|ого)\s+счет)\b",
        line,
    )
    contact_marker = re.search(r"\b(?:тел\.?|телефон|факс|fax|phone|mobile)\b", line)
    if re.search(r"\b(?:паспорт|passport)\b", line):
        if legal_or_financial_marker and not re.search(r"\b(?:серия|сер\.?|номер|№|no\.?)\b", line):
            return True
        return False
    if legal_or_financial_marker or contact_marker:
        return True
    return False


def has_passport_context_for_number(text: str, start: int, end: int) -> bool:
    if has_blank_passport_template_context(text, start, end):
        return False
    window = text[max(0, start - 220) : min(len(text), end + 220)].lower()
    prefix = text[max(0, start - 35) : start].lower()
    direct_label = bool(re.search(r"(?:паспорт|passport)\s*[:№#-]?\s*$", prefix))
    has_passport_word = bool(re.search(r"\b(?:паспорт|passport)\b", window))
    has_series_word = bool(re.search(r"\b(?:серия|сер\.?)\b", window))
    has_number_marker = "№" in window or bool(re.search(r"\b(?:номер|no\.?|n)\b", window))
    issuer_fields = count_present(
        window,
        (
            "выдан",
            "кем выдан",
            "дата выдачи",
            "код подразделения",
            "личный код",
        ),
    )
    person_fields = count_present(
        window,
        (
            "фамилия",
            "отчество",
            "дата рождения",
            "место рождения",
        ),
    )
    if re.search(r"\bимя\b", window):
        person_fields += 1
    return bool(
        direct_label
        or (has_passport_word and (has_series_word or has_number_marker or issuer_fields or person_fields))
        or ((has_series_word or has_number_marker) and issuer_fields and person_fields)
    )


def has_blank_passport_template_context(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 180) : min(len(text), end + 180)].lower()
    if re.search(
        r"\b(?:кбк|екс|бик|инн|кпп|октмо|расч[её]тн(?:ый|ого)\s+счет|банк\s+получателя)\b",
        window,
    ):
        return True
    placeholder_hits = len(re.findall(r"_{2,}|—{2,}|-{2,}|\.{3,}", window))
    passport_fields = count_present(
        window,
        (
            "паспорт",
            "выдан",
            "дата выдачи",
            "серия",
            "номер",
            "код подразделения",
        ),
    )
    filled_person_value = bool(
        re.search(r"\b(?:фамилия|имя|отчество)\b[^\n\r]{0,30}\b[А-ЯЁ][а-яё-]{2,}\b", window)
    )
    return bool(placeholder_hits >= 2 and passport_fields >= 2 and not filled_person_value)


def is_plausible_bank_card_match(text: str, match: re.Match[str]) -> bool:
    value = match.group(0)
    groups = re.findall(r"\d{4}", value)
    if len(groups) != 4:
        return False
    if all(1900 <= int(group) <= 2099 for group in groups):
        return False
    if has_technical_identifier_context(text, match.start(), match.end()):
        return False
    if not has_bank_card_context(text, match.start(), match.end()):
        return False
    return True


def has_bank_card_context(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 100) : min(len(text), end + 100)].lower()
    return bool(
        re.search(
            r"\b(?:карта|банковская\s+карта|номер\s+карты|сбербанк|visa|mastercard|mir|card|cardholder|pan|cvv|cvc)\b",
            window,
        )
    )


def is_plausible_snils_match(text: str, match: re.Match[str]) -> bool:
    if has_technical_identifier_context(text, match.start(), match.end()):
        return False
    window = text[max(0, match.start() - 100) : min(len(text), match.end() + 100)].lower()
    if re.search(r"\b(?:снилс|страховой\s+номер|snils)\b", window):
        return True
    return False


def has_driver_license_value_context(text: str) -> bool:
    return bool(
        re.search(
            r"(?is)\b(?:водительское\s+удостоверение|водительские\s+права|в/у|driver\s+license)\b"
            r"[^\n\r]{0,100}?(?:№|номер|серия|no\.?|n)?\s*\d{2}\s?\d{2}\s?\d{6}\b",
            text,
        )
    )


def find_contextual_passports(text: str) -> list[str]:
    matches: list[str] = []
    for pattern in PASSPORT_CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            if has_non_passport_number_context(text, match.start(), match.end()):
                continue
            if has_blank_passport_template_context(text, match.start(), match.end()):
                continue
            series = re.sub(r"\D+", "", match.group(1))
            number = re.sub(r"\D+", "", match.group(2))
            value = f"{series}{number}"
            if len(series) == 4 and len(number) == 6 and not validate_inn(value):
                matches.append(f"{series} {number}")
    return matches


def find_contextual_birth_dates(text: str) -> list[str]:
    matches: list[str] = []
    for pattern in BIRTH_DATE_CONTEXT_PATTERNS:
        for match in pattern.finditer(text):
            matches.append(match.group(1))
    return matches


def find_foreign_identity_documents(text: str) -> list[str]:
    normalized = normalize_for_identity_document_search(text)
    if not normalized:
        return []

    identity_marker = find_identity_document_marker(normalized)
    if not identity_marker:
        return []

    field_hits = sum(
        1
        for pattern in (
            r"\bsurname\b",
            r"\bgiven names?\b",
            r"\bopen names?\b",
            r"\bdate of birth\b",
            r"\bplace of birth\b",
            r"\bnationality\b",
            r"\bholder s signature\b",
            r"\bdocument no\b",
            r"\bsex\b",
            r"\bcislo dokladu\b",
            r"\bdatum narozeni\b",
            r"\bmisto narozeni\b",
            r"\bstatni obcanstvi\b",
            r"\bplatnost\b",
            r"\bjmeno\b",
            r"\bprijmeni\b",
        )
        if re.search(pattern, normalized)
    )
    date_hits = len(re.findall(r"\b\d{1,2}[./-]\d{1,2}[./-](?:\d{2}|\d{4})\b", text))
    document_number_hit = bool(
        re.search(
            r"\b(?:document|doklad|card|id)\s*(?:no|number|#)\b.{0,35}\b(?=[a-z0-9]*\d)[a-z0-9]{6,12}\b|"
            r"\b(?:cislo|no|number)\b.{0,20}\b(?=[a-z0-9]*\d)[a-z0-9]{6,12}\b",
            normalized,
        )
    )

    filled_identity_hit = bool(
        re.search(
            r"\b(?:surname|given names?|jmeno|prijmeni|nationality)\b\s+[a-z]{3,}(?:\s+[a-z]{3,}){0,2}\b",
            normalized,
        )
    )
    czech_identity_card_context = bool(
        re.search(r"\b(?:obcansk\w*|vncansk\w*)\s+(?:pr\w{2,8}|prokaz|paijuay)\b", normalized)
        or (
            re.search(r"\b(?:ceska|czech)\s+repub\w*\b", normalized)
            and re.search(r"\b(?:identification|dentification)\b", normalized)
        )
    )
    if czech_identity_card_context and date_hits >= 1:
        return [identity_marker or "czech identification card"]
    if document_number_hit or (field_hits >= 4 and date_hits >= 2 and filled_identity_hit):
        return [identity_marker]
    return []


def normalize_for_identity_document_search(text: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^a-zA-Z0-9./-]+", " ", ascii_text).lower()
    return re.sub(r"\s+", " ", normalized).strip()


def find_identity_document_marker(normalized_text: str) -> str | None:
    marker_patterns = (
        (r"\b(?:foreign|national|state)?\s*(?:identity|identification)\s+card\b", "foreign identity card"),
        (r"\b(?:id|identity)\s+document\b", "foreign identity document"),
        (r"\bnational\s+id\b", "foreign national id"),
        (r"\bobcansk\w*\s+pr\w{2,8}\b", "obcansky prukaz"),
        (r"\bczech\s+repub\w*.{0,30}\b(?:identity|identification|dentification)\b", "czech identification card"),
        (r"\b(?:identity|identification|dentification)\s+ca\w*\b", "foreign identity card"),
    )
    for pattern, label in marker_patterns:
        if re.search(pattern, normalized_text):
            return label
    return None


def count_present(content: str, phrases: tuple[str, ...]) -> int:
    return sum(1 for phrase in phrases if phrase in content)


def add_validation_stats(result: PIIResult, category: str, candidates: int, valid: int) -> None:
    if candidates <= 0:
        return
    result.metadata.setdefault("validation", {})[category] = {
        "candidates": candidates,
        "valid": valid,
        "rejected": candidates - valid,
    }


def build_pii_features(record: FileRecord, result: PIIResult, text: str, unique_full_names: set[str]) -> dict[str, object]:
    categories = set(result.categories)
    total_findings = sum(item.count for item in result.categories.values())
    weak_keyword_findings = sum(result.categories[name].count for name in categories & WEAK_KEYWORD_CATEGORIES)
    sensitive_findings = sum(
        result.categories[name].count
        for name in categories
        if name in DIRECT_IDENTIFIER_CATEGORIES | {"bank_card", "cvv"} | SPECIAL_CATEGORY_CATEGORIES
    )
    direct_identifier_findings = sum(result.categories[name].count for name in categories & DIRECT_IDENTIFIER_CATEGORIES)
    contact_findings = sum(result.categories[name].count for name in categories & CONTACT_CATEGORIES)
    financial_findings = sum(result.categories[name].count for name in categories & FINANCIAL_CATEGORIES)
    text_kchars = max(len(text), 1) / 1000
    identity_categories = DIRECT_IDENTIFIER_CATEGORIES | DEMOGRAPHIC_CATEGORIES | CONTACT_CATEGORIES | {"bank_card"}
    has_strong_id = bool(categories & DIRECT_IDENTIFIER_CATEGORIES)
    has_contact_or_demographic = bool(categories & {"birth_date", "address", "phone", "email"})
    is_structured = record.extension in {".csv", ".json", ".parquet", ".xlsx", ".xls"}
    is_image_or_scan = record.extension in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".gif", ".mp4", ".avi", ".mov", ".mkv", ".webm"} or (
        record.extension == ".pdf" and bool(result.metadata.get("extraction", {}).get("ocr_used"))
    )

    return {
        "has_passport_and_snils": {"passport_rf", "snils"} <= categories,
        "has_government_id_bundle": bool(categories & {"passport_rf", "foreign_id_document", "snils", "driver_license", "mrz"})
        and ("full_name" in categories or len(categories & DIRECT_IDENTIFIER_CATEGORIES) >= 2),
        "has_card_and_phone": {"bank_card", "phone"} <= categories,
        "has_payment_bundle": bool(categories & {"bank_card", "cvv"}) or {"bank_account", "bik"} <= categories,
        "has_contact_bundle": "full_name" in categories and len(categories & CONTACT_CATEGORIES) >= 2,
        "has_full_identity_bundle": (
            "full_name" in categories
            and (
                {"passport_rf", "snils"} <= categories
                or (has_strong_id and has_contact_or_demographic)
                or len(categories & identity_categories) >= 4
            )
        ),
        "unique_persons": len(unique_full_names),
        "total_findings": total_findings,
        "value_findings": max(total_findings - weak_keyword_findings, 0),
        "weak_keyword_findings": weak_keyword_findings,
        "sensitive_findings": sensitive_findings,
        "direct_identifier_findings": direct_identifier_findings,
        "contact_findings": contact_findings,
        "financial_findings": financial_findings,
        "category_count": len(categories),
        "sensitive_category_count": len(categories & (DIRECT_IDENTIFIER_CATEGORIES | {"bank_card", "cvv"} | SPECIAL_CATEGORY_CATEGORIES)),
        "text_length": len(text),
        "file_size_bytes": record.size_bytes,
        "is_structured": is_structured,
        "is_image_or_scan": is_image_or_scan,
        "pdn_density": round(total_findings / text_kchars, 3),
        "value_pdn_density": round(max(total_findings - weak_keyword_findings, 0) / text_kchars, 3),
    }


def normalize_person_name(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower().replace("ё", "е")


def add_matches(result: PIIResult, category: str, matches: Iterable[str], count_override: int | None = None) -> None:
    unique = []
    seen = set()
    for value in matches:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)

    count = count_override if count_override is not None else len(unique)
    if count <= 0:
        return

    samples = [mask_value(category, item) for item in unique[:3]]
    existing = result.categories.get(category)
    if existing:
        merged_samples = existing.samples_masked[:]
        for sample in samples:
            if sample not in merged_samples:
                merged_samples.append(sample)
        existing.count = max(existing.count, count)
        existing.samples_masked = merged_samples[:3]
        return

    result.categories[category] = CategoryFinding(count=count, samples_masked=samples)


def mask_value(category: str, value: str) -> str:
    value = str(value).strip()
    if category in {"email"}:
        left, _, domain = value.partition("@")
        return f"{left[:2]}***@{domain}" if domain else hash_value(value)
    if category == "foreign_id_document":
        return "identity_document_marker"
    if category in {
        "phone",
        "passport_rf",
        "snils",
        "inn",
        "inn_person",
        "inn_legal",
        "bank_card",
        "bank_account",
        "bik",
        "cvv",
        "birth_date",
    }:
        digits = re.sub(r"\D+", "", value)
        if len(digits) <= 4:
            return "*" * len(digits)
        return f"{digits[:2]}***{digits[-2:]}"
    if category == "full_name":
        parts = value.split()
        return " ".join(part[:1] + "***" for part in parts)
    if len(value) <= 4:
        return "***"
    return value[:2] + "***" + value[-1:]


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]

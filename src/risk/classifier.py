from __future__ import annotations

import math

from src.config import HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD, SENSITIVE_CATEGORIES
from src.models import FileRecord, PIIResult, RiskResult
from src.pii_detection.dictionaries import BUSINESS_CONTEXT_KEYWORDS


DIRECT_IDENTIFIER_CATEGORIES = {"passport_rf", "foreign_id_document", "snils", "inn_person", "driver_license", "mrz"}
CONTACT_CATEGORIES = {"phone", "email", "address"}
LEGAL_ENTITY_CATEGORIES = {"inn_legal", "bik", "bank_account"}
SPECIAL_CATEGORY_CATEGORIES = {"health", "religion", "political_views", "nationality", "race", "biometric"}
HIGH_IMPACT_CATEGORIES = DIRECT_IDENTIFIER_CATEGORIES | {"bank_card", "cvv"} | SPECIAL_CATEGORY_CATEGORIES
BENIGN_BUSINESS_CATEGORIES = {"full_name", "phone", "email", "address", "inn_legal", "bik", "bank_account"}
TABLE_EXTENSIONS = {".csv", ".xlsx", ".xls", ".parquet", ".json"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".gif"}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".mpeg", ".mpg"}


CATEGORY_POINTS = {
    "mrz": 6,
    "foreign_id_document": 6,
    "cvv": 6,
    "passport_rf": 5,
    "snils": 5,
    "driver_license": 5,
    "bank_card": 5,
    "biometric": 5,
    "inn_person": 4,
    "health": 4,
    "religion": 4,
    "political_views": 4,
    "nationality": 4,
    "race": 4,
    "birth_date": 2,
    "birth_place": 2,
    "bank_account": 2,
    "full_name": 2,
    "phone": 1,
    "email": 1,
    "address": 1,
    "inn_legal": 1,
    "bik": 1,
    "inn": 3,
}


def classify_risk(record: FileRecord, text: str, metadata: dict, pii_result: PIIResult, document_type: str) -> RiskResult:
    categories = set(pii_result.categories)
    features = pii_result.features or {}
    table_analysis = pii_result.metadata.get("table_analysis") or {}
    content = f"{record.relative_path} {text}".lower()
    relative_path = record.relative_path.lower()

    reasons: list[str] = []
    sensitivity_score = score_pii_sensitivity(pii_result, document_type, features, table_analysis, reasons)
    massiveness_score = score_massiveness(record, features, table_analysis, categories, document_type, reasons)
    context_score = score_context(record, content, categories, features, table_analysis, document_type, reasons)
    legitimacy_discount = score_legitimate_context(content, categories, features, table_analysis, document_type, reasons)

    if is_suspicious_storage_path(relative_path):
        context_score += 4
        reasons.append("Suspicious file or directory name (+4 context)")

    score = max(sensitivity_score + massiveness_score + context_score - legitimacy_discount, 0)
    reasons.insert(
        0,
        (
            "Risk components: "
            f"pii_sensitivity={sensitivity_score}, massiveness={massiveness_score}, "
            f"context_suspicion={context_score}, legitimate_context=-{legitimacy_discount}"
        ),
    )

    if score >= HIGH_RISK_THRESHOLD:
        level = "high"
    elif score >= MEDIUM_RISK_THRESHOLD:
        level = "medium"
    else:
        level = "low"

    include = should_include_in_report(
        record=record,
        score=score,
        level=level,
        categories=categories,
        features=features,
        table_analysis=table_analysis,
        document_type=document_type,
        context_score=context_score,
    )
    has_sensitive = bool(categories & HIGH_IMPACT_CATEGORIES) or int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0
    recommendation = build_recommendation(level, has_sensitive)
    return RiskResult(score=score, level=level, include_in_report=include, reasons=reasons, recommendation=recommendation)


def score_pii_sensitivity(
    pii_result: PIIResult,
    document_type: str,
    features: dict,
    table_analysis: dict,
    reasons: list[str],
) -> int:
    score = 0
    categories = set(pii_result.categories)
    weak_public_health = is_weak_public_health_context(categories, features, table_analysis, document_type)
    for category, finding in sorted(pii_result.categories.items()):
        if category == "health" and weak_public_health:
            points = 1
            bonus = 0
        else:
            points = CATEGORY_POINTS.get(category, 1)
            bonus = count_bonus(category, finding.count)
        contribution = points + bonus
        score += contribution
        if category == "health" and weak_public_health:
            reasons.append(f"{category}: {finding.count} public/regulatory mentions (+1 weak context)")
        elif bonus:
            reasons.append(f"{category}: {finding.count} found (+{points}+{bonus} count)")
        else:
            reasons.append(f"{category}: {finding.count} found (+{points})")

    if features.get("has_full_identity_bundle"):
        score += 6
        reasons.append("Full identity bundle: name plus strong identifiers/contact data (+6 sensitivity)")
    elif features.get("has_government_id_bundle"):
        score += 5
        reasons.append("Government ID bundle detected (+5 sensitivity)")

    if features.get("has_card_and_phone"):
        score += 5
        reasons.append("Bank card plus phone detected (+5 sensitivity)")
    elif features.get("has_payment_bundle") and not has_only_legal_payment_requisites(set(pii_result.categories)):
        score += 3
        reasons.append("Payment data bundle detected (+3 sensitivity)")

    if features.get("has_contact_bundle"):
        score += 3
        reasons.append("Name plus multiple contact categories detected (+3 sensitivity)")

    if pii_result.metadata.get("passport_context_detected"):
        score += 2
        reasons.append("Passport context confirmed around passport-like number (+2 sensitivity)")
    if pii_result.metadata.get("foreign_identity_document_detected"):
        score += 2
        reasons.append("Foreign identity document context detected (+2 sensitivity)")

    return score


def count_bonus(category: str, count: int) -> int:
    if count <= 1:
        return 0
    if category in HIGH_IMPACT_CATEGORIES:
        return min(5, int(math.log2(count)) + 1)
    if category in CONTACT_CATEGORIES | {"full_name", "birth_date"}:
        return min(3, int(math.log2(count)))
    if category in LEGAL_ENTITY_CATEGORIES:
        return min(2, int(math.log2(count)))
    return min(2, int(math.log2(count)))


def score_massiveness(
    record: FileRecord,
    features: dict,
    table_analysis: dict,
    categories: set[str],
    document_type: str,
    reasons: list[str],
) -> int:
    score = 0
    value_findings = int(features.get("value_findings") or 0)
    sensitive_findings = int(features.get("sensitive_findings") or 0)
    if is_weak_public_health_context(categories, features, table_analysis, document_type):
        sensitive_findings = max(sensitive_findings - int(features.get("sensitive_findings") or 0), 0)
    value_density = float(features.get("value_pdn_density") or 0.0)
    unique_persons = int(features.get("unique_persons") or 0)

    if value_findings >= 30:
        score += 5
        reasons.append("Many non-keyword PII findings (>=30) (+5 massiveness)")
    elif value_findings >= 10:
        score += 3
        reasons.append("Many non-keyword PII findings (>=10) (+3 massiveness)")

    if sensitive_findings >= 10:
        score += 4
        reasons.append("Many sensitive identifiers (>=10) (+4 massiveness)")
    elif sensitive_findings >= 3:
        score += 2
        reasons.append("Several sensitive identifiers (>=3) (+2 massiveness)")

    if value_density >= 2.0 and value_findings >= 5:
        score += 3
        reasons.append("High value PII density (+3 massiveness)")
    elif value_density >= 0.8 and value_findings >= 3:
        score += 1
        reasons.append("Elevated value PII density (+1 massiveness)")

    if unique_persons >= 20:
        score += 5
        reasons.append("Many distinct full names (>=20) (+5 massiveness)")
    elif unique_persons >= 5:
        score += 3
        reasons.append("Multiple distinct full names (>=5) (+3 massiveness)")

    if table_analysis.get("status") == "ok":
        rows_with_pii = int(table_analysis.get("rows_with_pii") or 0)
        rows_with_sensitive = int(table_analysis.get("rows_with_sensitive_pii") or 0)
        rows_with_combo = int(table_analysis.get("rows_with_sensitive_combo") or 0)
        pii_row_ratio = float(table_analysis.get("pii_row_ratio") or 0.0)
        combo_row_ratio = float(table_analysis.get("combo_row_ratio") or 0.0)
        sensitive_column_count = int(table_analysis.get("sensitive_column_count") or 0)

        if rows_with_combo >= 10 or combo_row_ratio >= 0.2:
            score += 8
            reasons.append("Table has many rows with sensitive PII combinations (+8 massiveness)")
        elif rows_with_combo:
            score += 5
            reasons.append(f"Table has {rows_with_combo} rows with sensitive PII combinations (+5 massiveness)")

        if rows_with_sensitive >= 20:
            score += 6
            reasons.append("Table has many rows with sensitive PII (+6 massiveness)")
        elif rows_with_sensitive >= 3:
            score += 4
            reasons.append(f"Table has {rows_with_sensitive} rows with sensitive PII (+4 massiveness)")

        if rows_with_pii >= 50 or pii_row_ratio >= 0.3:
            score += 4
            reasons.append("Table has broad PII coverage across rows (+4 massiveness)")
        elif rows_with_pii >= 10:
            score += 2
            reasons.append(f"Table has {rows_with_pii} rows with PII (+2 massiveness)")

        if sensitive_column_count >= 3:
            score += 3
            reasons.append("Table has multiple sensitive PII-bearing columns (+3 massiveness)")

    if record.extension in TABLE_EXTENSIONS and value_findings >= 5:
        score += 2
        reasons.append("Structured file contains repeated PII-like values (+2 massiveness)")

    return score


def score_context(
    record: FileRecord,
    content: str,
    categories: set[str],
    features: dict,
    table_analysis: dict,
    document_type: str,
    reasons: list[str],
) -> int:
    score = 0

    if record.extension in IMAGE_EXTENSIONS and categories & HIGH_IMPACT_CATEGORIES:
        score += 5
        reasons.append("Image file contains high-impact PII (+5 context)")
    elif record.extension in VIDEO_EXTENSIONS and categories & HIGH_IMPACT_CATEGORIES:
        score += 5
        reasons.append("Video frame OCR contains high-impact PII (+5 context)")
    elif metadata_indicates_scan(features, record, categories):
        score += 4
        reasons.append("File looks like scan/image with sensitive PII (+4 context)")

    if has_dump_or_backup_context(record.relative_path, content):
        score += 5
        reasons.append("Dump/backup/export context (+5 context)")

    if document_type in {"скан паспорта", "водительское удостоверение", "удостоверение личности"}:
        score += 5
        reasons.append(f"Document type is {document_type} (+5 context)")
    elif document_type == "таблица с идентификаторами":
        score += 4
        reasons.append("Document type is identifier table (+4 context)")
    elif document_type == "выгрузка или дамп":
        score += 5
        reasons.append("Document type is export/dump (+5 context)")
    elif document_type == "медицинский документ" and "health" in categories:
        score += 3
        reasons.append("Medical context with health data (+3 context)")
    elif document_type == "личная расписка" and categories & (DIRECT_IDENTIFIER_CATEGORIES | CONTACT_CATEGORIES):
        score += 3
        reasons.append("Personal receipt with identifiers/contact data (+3 context)")

    if table_analysis.get("status") == "ok" and int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0:
        score += 2
        reasons.append("Row-level sensitive combinations confirmed (+2 context)")

    return score


def metadata_indicates_scan(features: dict, record: FileRecord, categories: set[str]) -> bool:
    return bool(features.get("is_image_or_scan")) and bool(categories & HIGH_IMPACT_CATEGORIES) and record.extension != ".txt"


def score_legitimate_context(
    content: str,
    categories: set[str],
    features: dict,
    table_analysis: dict,
    document_type: str,
    reasons: list[str],
) -> int:
    discount = 0
    high_impact_present = bool(categories & HIGH_IMPACT_CATEGORIES)
    table_combo = int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0

    if document_type == "публичная политика или условия сервиса" and not table_combo:
        value_categories = categories - {"address", "phone", "email", "inn_legal", "bik", "bank_account", "full_name"}
        if not value_categories:
            discount += 8
            reasons.append("Public policy/terms with only contact or legal-entity data (-8 legitimate context)")
        elif not (categories & {"passport_rf", "foreign_id_document", "snils", "inn_person", "bank_card", "cvv", "mrz"}):
            discount += 10
            reasons.append("Public policy/terms context lowers weak special-category mentions (-10 legitimate context)")

    if document_type == "публичный регламент или правила приема" and not table_combo:
        if is_weak_public_health_context(categories, features, table_analysis, document_type) or categories <= {
            "health",
            "address",
            "phone",
            "email",
            "inn_legal",
            "bik",
            "bank_account",
            "full_name",
        }:
            discount += 8
            reasons.append("Public admission/regulatory document with weak PII mentions (-8 legitimate context)")

    if is_weak_special_category_context(categories, features, table_analysis, document_type):
        discount += 8
        reasons.append("Special-category words without a concrete person anchor (-8 legitimate context)")

    business_hits = [keyword for keyword in BUSINESS_CONTEXT_KEYWORDS if keyword in content]
    if business_hits and not (categories & {"bank_card", "cvv", "mrz", "health", "biometric", "inn_person"}):
        discount += 4
        reasons.append("Formal business context without personal high-impact identifiers (-4 legitimate context)")

    if document_type in {"счет", "акт", "накладная", "договор", "приказ"} and categories <= BENIGN_BUSINESS_CATEGORIES:
        discount += 5
        reasons.append("Likely legitimate business document with benign/legal-entity categories (-5 legitimate context)")

    if categories and categories <= {"address", "phone", "email", "inn_legal", "bik", "bank_account"}:
        discount += 4
        reasons.append("Only contact/legal-entity requisites found (-4 legitimate context)")

    if not high_impact_present and not table_combo and categories <= BENIGN_BUSINESS_CATEGORIES:
        discount += 2
        reasons.append("No high-impact personal category found (-2 legitimate context)")

    return min(discount, 12)


def is_weak_public_health_context(
    categories: set[str],
    features: dict,
    table_analysis: dict,
    document_type: str,
) -> bool:
    if "health" not in categories:
        return False
    if document_type not in {"публичный регламент или правила приема", "публичная политика или условия сервиса"}:
        return False
    if int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0:
        return False
    if categories & (DIRECT_IDENTIFIER_CATEGORIES | {"birth_date", "birth_place", "bank_card", "cvv"}):
        return False
    if not categories <= {"health", "address", "phone", "email", "inn_legal", "bik", "bank_account", "full_name"}:
        return False
    if int(features.get("unique_persons") or 0) > 0:
        return False
    return True


def should_include_in_report(
    record: FileRecord,
    score: int,
    level: str,
    categories: set[str],
    features: dict,
    table_analysis: dict,
    document_type: str,
    context_score: int,
) -> bool:
    if not categories:
        return False

    table_combo = int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0
    table_sensitive_mass = int(table_analysis.get("rows_with_sensitive_pii") or 0) >= 3
    strong_personal_identifier = bool(categories & (DIRECT_IDENTIFIER_CATEGORIES | {"bank_card", "cvv"}))
    identity_bundle = bool(features.get("has_full_identity_bundle") or features.get("has_government_id_bundle"))
    contact_bundle = bool(features.get("has_contact_bundle"))
    payment_bundle = bool(features.get("has_card_and_phone") or features.get("has_payment_bundle"))
    suspicious_context = context_score >= 5
    suspicious_storage = is_suspicious_storage_path(record.relative_path)
    value_findings = int(features.get("value_findings") or 0)
    structured_mass_dump = (
        record.extension in TABLE_EXTENSIONS
        and suspicious_storage
        and value_findings >= 20
        and len(categories & (DIRECT_IDENTIFIER_CATEGORIES | CONTACT_CATEGORIES | {"inn_person"})) >= 2
    )
    personal_storage_contact_leak = is_personal_storage_contact_leak(record.relative_path, categories)

    if is_weak_special_category_context(categories, features, table_analysis, document_type):
        return False

    if is_public_web_path(record.relative_path) and not table_combo and value_findings < 10 and not identity_bundle:
        return False

    if is_public_low_risk_document(record.relative_path, document_type, categories, features, table_analysis):
        return False

    if (
        document_type in {"приказ", "публичный регламент или правила приема", "публичная политика или условия сервиса"}
        and not suspicious_storage
        and not table_combo
        and categories <= {"snils", "full_name", "address", "phone", "email", "inn_legal", "bik", "bank_account"}
    ):
        return False

    low_value_only = categories <= {"address", "phone", "email", "inn_legal", "bik", "bank_account", "full_name"}
    if personal_storage_contact_leak and level in {"medium", "high"}:
        return True

    if low_value_only and not table_combo and not suspicious_context:
        return False

    if level == "high":
        return (
            table_combo
            or table_sensitive_mass
            or identity_bundle
            or payment_bundle
            or structured_mass_dump
            or (strong_personal_identifier and suspicious_context)
        )

    if level == "medium":
        return table_combo or identity_bundle or payment_bundle or (
            contact_bundle and (strong_personal_identifier or suspicious_context or score >= HIGH_RISK_THRESHOLD)
        )

    return False


def has_only_legal_payment_requisites(categories: set[str]) -> bool:
    return bool(categories & {"bank_account", "bik", "inn_legal"}) and not bool(categories & {"bank_card", "cvv"})


def is_weak_special_category_context(
    categories: set[str],
    features: dict,
    table_analysis: dict,
    document_type: str,
) -> bool:
    if not categories & SPECIAL_CATEGORY_CATEGORIES:
        return False
    if int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0:
        return False
    if categories & (DIRECT_IDENTIFIER_CATEGORIES | {"bank_card", "cvv", "birth_date", "birth_place"}):
        return False
    if int(features.get("unique_persons") or 0) > 0:
        return False
    allowed = SPECIAL_CATEGORY_CATEGORIES | {"address", "phone", "email", "inn_legal", "bik", "bank_account"}
    if not categories <= allowed:
        return False
    return document_type in {
        "публичная политика или условия сервиса",
        "публичный регламент или правила приема",
        "медицинский документ",
        "согласие на обработку ПДн",
        "неизвестный документ",
    }


def is_suspicious_storage_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/").lower()
    if is_public_web_path(relative_path):
        return False
    strong_markers = (
        "billing",
        "employes",
        "employees",
        "мои бумажки",
        "архив сканы",
        "личное",
        "backup",
        "dump",
        "temp",
        "tmp",
        "passport",
        "паспорт",
        "snils",
        "снилс",
        "card",
        "карта",
        "копия",
        "photo",
        "фото",
        "scan",
        "сканы",
    )
    return any(marker in normalized for marker in strong_markers)


def is_public_web_path(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/").lower()
    return "выгрузки/сайты" in normalized or "выгрузки/сайты" in normalized


def is_public_low_risk_document(
    relative_path: str,
    document_type: str,
    categories: set[str],
    features: dict,
    table_analysis: dict,
) -> bool:
    if int(table_analysis.get("rows_with_sensitive_combo") or 0) > 0:
        return False

    normalized = relative_path.replace("\\", "/").lower()
    public_doc_type = document_type in {
        "публичный регламент или правила приема",
        "публичная политика или условия сервиса",
    }
    public_path_marker = any(
        marker in normalized
        for marker in (
            "samoobsled",
            "otchet",
            "отчет",
            "публичн",
            "fin_result",
            "координаты для связи",
            "03-5-01-005",
        )
    )
    if not (public_doc_type or public_path_marker or is_public_web_path(relative_path)):
        return False

    high_confidence = categories & (DIRECT_IDENTIFIER_CATEGORIES | {"bank_card", "cvv", "mrz"})
    if not high_confidence:
        return True

    if "координаты для связи" in normalized and categories <= {
        "full_name",
        "phone",
        "email",
        "address",
        "snils",
    }:
        return True

    if int(features.get("value_findings") or 0) < 5 and not bool(features.get("has_full_identity_bundle")):
        return True

    return False


def is_personal_storage_contact_leak(relative_path: str, categories: set[str]) -> bool:
    if "full_name" not in categories or not (categories & CONTACT_CATEGORIES):
        return False
    normalized = relative_path.replace("\\", "/").lower()
    personal_markers = (
        "мои бумажки",
        "личное",
        "home_office",
        "home-office",
        "home office",
        "dostavka",
        "доставка",
        "propusk",
        "пропуск",
        "zayavka",
        "заявка",
        "zayavlenie",
        "заявление",
    )
    return any(marker in normalized for marker in personal_markers)


def has_dump_or_backup_context(relative_path: str, content: str) -> bool:
    normalized_path = relative_path.replace("\\", "/").lower()
    if is_public_web_path(relative_path):
        return False
    if any(word in normalized_path for word in ("dump", "backup", "резервная копия")):
        return True
    if any(word in normalized_path for word in ("billing", "employes", "employees", "мои бумажки")):
        return True
    return any(word in content for word in ("dump", "backup", "резервная копия"))


def build_recommendation(level: str, has_sensitive: bool) -> str:
    if level == "high" and has_sensitive:
        return "Ручная проверка в первую очередь; при подтверждении перенести в защищенный контур или удалить при отсутствии основания хранения."
    if level == "medium":
        return "Ручная проверка; уточнить основание хранения и необходимость маскирования или переноса."
    return "Не включать в приоритетный отчет; хранить только технические признаки анализа."

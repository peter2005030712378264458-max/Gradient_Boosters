from __future__ import annotations

import re

from src.models import FileRecord, PIIResult


def detect_document_type(record: FileRecord, text: str, metadata: dict, pii_result: PIIResult) -> str:
    content = f"{record.relative_path} {text}".lower()
    categories = set(pii_result.categories)

    if any(
        phrase in content
        for phrase in (
            "политика конфиденциальности",
            "privacy policy",
            "terms of service",
            "пользовательское соглашение",
            "условия использования",
        )
    ):
        return "публичная политика или условия сервиса"
    if any(
        phrase in content
        for phrase in (
            "правила приема",
            "правила приёма",
            "порядок приема",
            "порядок приёма",
            "прием на обучение",
            "приём на обучение",
            "вступительных испытаний",
            "поступающие",
        )
    ) and any(word in content for word in ("университет", "обучение", "образовательн", "бакалавриат", "магистратур")):
        return "публичный регламент или правила приема"
    if "согласие на обработ" in content and "персональн" in content:
        return "согласие на обработку ПДн"
    if any(word in content for word in ("паспорт", "passport")) or "passport_rf" in categories:
        if record.extension in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".gif"}:
            return "скан паспорта"
        if record.extension == ".pdf" and (
            pii_result.metadata.get("passport_context_detected") or len(text) < 3000 or metadata.get("ocr_used")
        ):
            return "скан паспорта"
    if "foreign_id_document" in categories:
        return "удостоверение личности"
    if "driver_license" in categories or "водительское удостоверение" in content:
        return "водительское удостоверение"
    if "bank_card" in categories or "cvv" in categories:
        return "банковская карта или платежный документ"
    if "health" in categories:
        return "медицинский документ"
    table_analysis = pii_result.metadata.get("table_analysis") or {}
    if table_analysis.get("rows_with_sensitive_combo", 0) > 0:
        return "таблица с идентификаторами"
    if record.extension in {".csv", ".xlsx", ".xls", ".parquet"} and len(categories - {"inn_legal", "bik", "bank_account"}) >= 3:
        return "таблица с идентификаторами"
    if any(word in content for word in ("dump", "backup", "выгрузка", "резервная копия")):
        return "выгрузка или дамп"
    if any(word in content for word in ("расписка", "обязуюсь", "получил денежные средства")):
        return "личная расписка"
    if any(word in content for word in ("счет-фактура", "счет на оплату", "расчетный счет")):
        return "счет"
    if "накладная" in content:
        return "накладная"
    if "приказ" in content:
        return "приказ"
    if "договор" in content:
        return "договор"
    if re.search(r"\bакт\b", content):
        return "акт"
    if record.extension in {".jpg", ".jpeg", ".png", ".gif"}:
        return "изображение или скриншот"
    return "неизвестный документ"

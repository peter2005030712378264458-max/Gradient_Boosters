from __future__ import annotations

import re


PASSPORT_CONTEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?is)\bпаспорт(?:\s+рф|\s+гражданина\s+рф)?\b.{0,120}?"
        r"(?:серия\s*)?(\d{2}\s?\d{2}).{0,80}?"
        r"(?:№|номер|no\.?|n\s*)?\s*(\d{6})\b"
    ),
    re.compile(
        r"(?is)\b(?:серия\s*)?(\d{2}\s?\d{2}).{0,40}?"
        r"(?:№|номер|no\.?|n\s*)\s*(\d{6})\b.{0,80}?\bпаспорт\b"
    ),
    re.compile(
        r"(?is)\b(?:серия|сер\.?)\s*(\d{2}\s?\d{2})\b.{0,80}?"
        r"\b(?:номер|№|no\.?|n)\s*(\d{6})\b"
    ),
)

BIRTH_DATE_VALUE = r"(?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:19|20)\d{2}"

BIRTH_DATE_CONTEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"(?is)\b(?:"
        rf"дата\s+рождения|дата_рождения|д\.?\s*р\.?|"
        rf"родил(?:ся|ась)?|год\s+рождения|"
        rf"birth[_\s-]*date|date[_\s-]*of[_\s-]*birth|dob|born"
        rf")\b[^\n\r]{{0,80}}?\b({BIRTH_DATE_VALUE})\b"
    ),
    re.compile(
        rf"(?is)\b({BIRTH_DATE_VALUE})\b[^\n\r]{{0,50}}?\b(?:"
        rf"дата\s+рождения|дата_рождения|д\.?\s*р\.?|"
        rf"birth[_\s-]*date|date[_\s-]*of[_\s-]*birth|dob"
        rf")\b"
    ),
)


PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(
        r"(?ix)"
        r"(?<!\d)(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"
        r"|(?<!\d)\(\s*\d{3}\s*\)\s*\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"
        r"|\b(?:тел(?:ефон)?|phone|mobile)\b\s*[:№#-]?\s*(?:\+7|8)?[\s(-]*\d{3}[\s)-]*\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"
    ),
    "passport_rf": re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b"),
    "snils": re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}[- ]?\d{2}\b"),
    "inn": re.compile(r"\b(?:\d{10}|\d{12})\b"),
    "bank_card": re.compile(r"(?<![A-Za-z0-9])(?:\d{4}[ -]?){3}\d{4}(?![A-Za-z0-9])"),
    "bik": re.compile(r"(?i)\b(?:БИК|BIK)\s*[:№#-]?\s*(\d{9})\b"),
    "bank_account": re.compile(r"(?i)\b(?:р/с|счет|расчетный счет|лицевой счет)\s*[:№#-]?\s*(\d{20})\b"),
    "cvv": re.compile(r"(?i)\b(?:CVV|CVC|код безопасности)\s*[:№#-]?\s*(\d{3})\b"),
    "mrz": re.compile(r"\b(?:P<|ID|I<)[A-Z0-9<]{20,}\b"),
    "full_name": re.compile(r"\b[А-ЯЁ][а-яё-]{2,}\s+[А-ЯЁ][а-яё-]{2,}(?:\s+[А-ЯЁ][а-яё-]{2,})?\b"),
}

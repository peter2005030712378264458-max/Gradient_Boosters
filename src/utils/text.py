from __future__ import annotations

import re


LIGATURE_TRANSLATION = str.maketrans(
    {
        "\ufb00": "ff",
        "\ufb01": "fi",
        "\ufb02": "fl",
        "\ufb03": "ffi",
        "\ufb04": "ffl",
        "\ufb05": "st",
        "\ufb06": "st",
    }
)


COMMON_PDF_LIGATURE_REPAIRS = {
    "reect": "reflect",
    "reects": "reflects",
    "reected": "reflected",
    "reecting": "reflecting",
    "eect": "effect",
    "eects": "effects",
    "eected": "effected",
    "eective": "effective",
    "eectively": "effectively",
    "dene": "define",
    "denes": "defines",
    "dened": "defined",
    "dening": "defining",
    "denition": "definition",
    "denitions": "definitions",
    "nd": "find",
    "nds": "finds",
    "nding": "finding",
    "specic": "specific",
    "specically": "specifically",
    "servicespecic": "service-specific",
    "articial": "artificial",
    "articially": "artificially",
    "identier": "identifier",
    "identiers": "identifiers",
    "aliate": "affiliate",
    "aliates": "affiliates",
    "aliated": "affiliated",
    "prole": "profile",
    "proles": "profiles",
    "verication": "verification",
    "conrm": "confirm",
    "conrms": "confirms",
    "conrmed": "confirmed",
    "conrming": "confirming",
    "congure": "configure",
    "congures": "configures",
    "congured": "configured",
    "conguring": "configuring",
    "oer": "offer",
    "oers": "offers",
    "oered": "offered",
    "oering": "offering",
}

COMMON_PDF_LIGATURE_RE = re.compile(
    r"\b(" + "|".join(re.escape(item) for item in sorted(COMMON_PDF_LIGATURE_REPAIRS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


def normalize_text(text: str) -> str:
    text = text.translate(LIGATURE_TRANSLATION)
    text = re.sub(r"(?<=[A-Za-zА-Яа-яЁё])\x00(?=[A-Za-zА-Яа-яЁё])", "", text)
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = repair_common_pdf_ligature_loss(text)
    return text.strip()


def repair_common_pdf_ligature_loss(text: str) -> str:
    matches = list(COMMON_PDF_LIGATURE_RE.finditer(text[:20_000]))
    if len(matches) < 2:
        return text

    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        replacement = COMMON_PDF_LIGATURE_REPAIRS[value.lower()]
        if value.isupper():
            return replacement.upper()
        if value[0].isupper():
            return replacement.capitalize()
        return replacement

    return COMMON_PDF_LIGATURE_RE.sub(replace, text)


def truncate_text(text: str, max_chars: int = 5_000_000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars]

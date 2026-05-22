from __future__ import annotations

import re


COMMON_FIRST_NAMES = {
    "александр",
    "александра",
    "алексей",
    "алена",
    "алина",
    "анастасия",
    "анатолий",
    "андрей",
    "анна",
    "антон",
    "артем",
    "вера",
    "виктор",
    "виктория",
    "владимир",
    "владислав",
    "галина",
    "дарья",
    "денис",
    "дмитрий",
    "евгений",
    "евгения",
    "екатерина",
    "елена",
    "иван",
    "игорь",
    "илья",
    "инна",
    "ирина",
    "кирилл",
    "константин",
    "ксения",
    "любовь",
    "людмила",
    "максим",
    "марина",
    "мария",
    "михаил",
    "наталья",
    "никита",
    "николай",
    "оксана",
    "олег",
    "ольга",
    "павел",
    "петр",
    "пётр",
    "роман",
    "светлана",
    "сергей",
    "станислав",
    "татьяна",
    "юлия",
    "юрий",
}

FULL_NAME_STOPWORDS = {
    "адрес",
    "акт",
    "банк",
    "бик",
    "город",
    "гражданин",
    "гражданина",
    "договор",
    "документ",
    "заказчик",
    "заявление",
    "инн",
    "исполнитель",
    "копия",
    "накладная",
    "номер",
    "организация",
    "паспорт",
    "приказ",
    "россия",
    "российская",
    "свидетельство",
    "серия",
    "снилс",
    "сторона",
    "стороны",
    "счет",
    "таблица",
    "федерация",
}

PATRONYMIC_SUFFIXES = (
    "вич",
    "вна",
    "ич",
    "ична",
    "оглы",
    "кызы",
)

SURNAME_SUFFIXES = (
    "ов",
    "ова",
    "ев",
    "ева",
    "ёв",
    "ёва",
    "ин",
    "ина",
    "ын",
    "ына",
    "ский",
    "ская",
    "цкий",
    "цкая",
    "ской",
    "ская",
    "енко",
    "ко",
    "ук",
    "юк",
    "ичева",
    "ичев",
)


def filter_full_name_matches(matches: list[str]) -> list[str]:
    filtered: list[str] = []
    for match in matches:
        candidate = normalize_candidate(match)
        parts = candidate.split()
        if is_likely_full_name(parts):
            filtered.append(candidate)
    return filtered


def normalize_candidate(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip(" ,.;:()[]{}")


def is_likely_full_name(parts: list[str]) -> bool:
    if len(parts) not in {2, 3}:
        return False
    normalized = [normalize_word(part) for part in parts]
    if any(part in FULL_NAME_STOPWORDS for part in normalized):
        return False

    if len(parts) == 2:
        first, second = normalized
        return (is_first_name(first) and is_surname(second)) or (is_surname(first) and is_first_name(second))

    surname, first_name, patronymic = normalized
    return is_surname(surname) and is_first_name(first_name) and is_patronymic(patronymic)


def normalize_word(value: str) -> str:
    return value.lower().replace("ё", "е").strip("-")


def is_first_name(value: str) -> bool:
    return value in {name.replace("ё", "е") for name in COMMON_FIRST_NAMES}


def is_patronymic(value: str) -> bool:
    return value.endswith(PATRONYMIC_SUFFIXES)


def is_surname(value: str) -> bool:
    return value.endswith(SURNAME_SUFFIXES)

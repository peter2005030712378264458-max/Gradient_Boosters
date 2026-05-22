from __future__ import annotations

import re


def only_digits(value: str) -> str:
    return re.sub(r"\D+", "", value)


def luhn_check(value: str) -> bool:
    digits = [int(ch) for ch in only_digits(value)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def validate_snils(value: str) -> bool:
    digits = only_digits(value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    number = digits[:9]
    checksum = int(digits[9:])
    control = sum(int(number[i]) * (9 - i) for i in range(9))
    if control < 100:
        expected = control
    elif control in (100, 101):
        expected = 0
    else:
        expected = control % 101
        if expected == 100:
            expected = 0
    return checksum == expected


def validate_inn(value: str) -> bool:
    digits = only_digits(value)
    if len(digits) == 10:
        factors = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        control = sum(int(digits[i]) * factors[i] for i in range(9)) % 11 % 10
        return control == int(digits[9])
    if len(digits) == 12:
        factors_11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        factors_12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        control_11 = sum(int(digits[i]) * factors_11[i] for i in range(10)) % 11 % 10
        control_12 = sum(int(digits[i]) * factors_12[i] for i in range(11)) % 11 % 10
        return control_11 == int(digits[10]) and control_12 == int(digits[11])
    return False

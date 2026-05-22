# Инструкция по запуску PII Leak Pipeline

Эта инструкция относится к проекту в папке `pii_leak_pipeline`.

Проект запускается одним файлом:

```bash
python run_pipeline.py --input-dir "<путь к папке с исходными файлами>"
```

`run_pipeline.py` последовательно выполняет:

1. `main.py` - парсит исходные файлы и создает `.txt`.
2. `reprocess_from_txt.py` - анализирует готовые `.txt`.
3. Создает `final/leaked_paths.txt` - итоговый список путей к файлам-утечкам.

## Что нужно установить

Обязательно:

- Python 3.10, 3.11, 3.12 или 3.13 Рекомендуется Python 3.11, 3.12 или 3.13
- Python-зависимости из `requirements.txt`.

Для OCR изображений и сканированных PDF:

- `tesseract`
- языковые данные Tesseract для `rus` и `eng`

Для обработки видео:

- `ffmpeg`
- `ffprobe`

Опционально:

- `textract` для дополнительной поддержки старых `.doc` файлов. В `requirements.txt` он оставлен закомментированным, потому что на разных ОС может требовать дополнительные системные пакеты.

## macOS

### 1. Установить Homebrew

Если Homebrew уже установлен, этот шаг пропустите.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Установить Python и системные утилиты

```bash
brew install python@3.12
brew install tesseract
brew install tesseract-lang
brew install ffmpeg
```

Проверка:

```bash
python3.12 --version
tesseract --version
ffmpeg -version
ffprobe -version
tesseract --list-langs
```

В списке языков Tesseract должны быть `rus` и `eng`.

### 3. Создать и активировать виртуальное окружение

Перейдите в папку проекта:

```bash
cd "/path/to/pii_leak_pipeline"
```

Создайте окружение:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Обновите pip:

```bash
python -m pip install --upgrade pip setuptools wheel
```

### 4. Установить Python-зависимости

```bash
pip install -r requirements.txt
```

### 5. Запустить полный pipeline

```bash
python run_pipeline.py --input-dir "/path/to/share" --workers 4
```

Пример с явной папкой результата:

```bash
python run_pipeline.py \
  --input-dir "/path/to/share" \
  --run-dir "./runs/manual_run" \
  --workers 4 \
  --pdf-workers 2
```

Также можно запускать через shell-обертку:

```bash
./run_pipeline.sh --input-dir "/path/to/share" --workers 4
```

## Windows

Команды ниже рассчитаны на PowerShell.

### 1. Установить Python

Рекомендуемый вариант - установить Python 3.11 или 3.12 с официального сайта Python.

Во время установки включите опцию:

```text
Add python.exe to PATH
```

Проверка:

```powershell
py --version
python --version
```

### 2. Установить Chocolatey

Если Chocolatey уже установлен, этот шаг пропустите.

Откройте PowerShell от имени администратора и выполните:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

После установки перезапустите PowerShell.

### 3. Установить системные утилиты

Откройте PowerShell от имени администратора:

```powershell
choco install tesseract -y
choco install ffmpeg -y
```

Проверка:

```powershell
tesseract --version
ffmpeg -version
ffprobe -version
tesseract --list-langs
```

В списке языков Tesseract должны быть `rus` и `eng`.

Если `rus` отсутствует, нужно добавить файл `rus.traineddata` в папку `tessdata` установленного Tesseract. Обычно это одна из папок:

```text
C:\Program Files\Tesseract-OCR\tessdata
C:\tools\tesseract\tessdata
```

После добавления проверьте еще раз:

```powershell
tesseract --list-langs
```

### 4. Создать и активировать виртуальное окружение

Перейдите в папку проекта:

```powershell
cd "C:\path\to\pii_leak_pipeline"
```

Создайте окружение:

```powershell
py -3.12 -m venv .venv
```

Если Python 3.12 не установлен, используйте:

```powershell
py -3.11 -m venv .venv
```

Активируйте окружение:

```powershell
.\.venv\Scripts\Activate.ps1
```

Если PowerShell запрещает запуск скриптов активации, выполните:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\.venv\Scripts\Activate.ps1
```

Обновите pip:

```powershell
python -m pip install --upgrade pip setuptools wheel
```

### 5. Установить Python-зависимости

```powershell
pip install -r requirements.txt
```

### 6. Запустить полный pipeline

```powershell
python .\run_pipeline.py --input-dir "D:\path\to\share" --workers 4
```

Пример с явной папкой результата:

```powershell
python .\run_pipeline.py `
  --input-dir "D:\path\to\share" `
  --run-dir ".\runs\manual_run" `
  --workers 4 `
  --pdf-workers 2
```

Также можно запускать через PowerShell-обертку:

```powershell
.\run_pipeline.ps1 -InputDir "D:\path\to\share" -Workers 4
```

## Linux

Команды ниже рассчитаны на Ubuntu/Debian. Для других дистрибутивов используйте соответствующий пакетный менеджер.

### 1. Установить Python и системные утилиты

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
sudo apt install -y tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng
sudo apt install -y ffmpeg
```

Для некоторых Python-пакетов могут понадобиться базовые инструменты сборки:

```bash
sudo apt install -y build-essential python3-dev
```

Проверка:

```bash
python3 --version
tesseract --version
ffmpeg -version
ffprobe -version
tesseract --list-langs
```

В списке языков Tesseract должны быть `rus` и `eng`.

### 2. Создать и активировать виртуальное окружение

Перейдите в папку проекта:

```bash
cd "/path/to/pii_leak_pipeline"
```

Создайте окружение:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Обновите pip:

```bash
python -m pip install --upgrade pip setuptools wheel
```

### 3. Установить Python-зависимости

```bash
pip install -r requirements.txt
```

### 4. Запустить полный pipeline

```bash
python run_pipeline.py --input-dir "/path/to/share" --workers 4
```

Пример с явной папкой результата:

```bash
python run_pipeline.py \
  --input-dir "/path/to/share" \
  --run-dir "./runs/manual_run" \
  --workers 4 \
  --pdf-workers 2
```

Также можно запускать через shell-обертку:

```bash
./run_pipeline.sh --input-dir "/path/to/share" --workers 4
```

## Где искать результаты

Если `--run-dir` не указан, результат будет создан автоматически:

```text
runs/run_YYYY-MM-DD_HH-MM-SS/
```

Структура результата:

```text
<run-dir>/
  parsed/
    extracted_texts/
    pii_findings/
    reports/
    logs/
  final/
    pii_findings/
    reports/
    logs/
    leaked_paths.txt
```

Основные файлы:

```text
<run-dir>/parsed/extracted_texts/          # .txt, созданные парсером
<run-dir>/final/reports/final_report.json # финальный JSON-отчет второго этапа
<run-dir>/final/reports/final_report.csv  # финальный CSV-отчет второго этапа
<run-dir>/final/reports/final_report.md   # финальный Markdown-отчет второго этапа
<run-dir>/final/leaked_paths.txt          # итоговый список путей к утечкам
```

Формат `leaked_paths.txt`:

```text
/Прочее/P877_28052020.pdf
/Выгрузки/Сайты/page_001.html
```

Одна строка - один путь. Пути записываются относительно папки, переданной в `--input-dir`.

## Полезные параметры запуска

```bash
python run_pipeline.py \
  --input-dir "/path/to/share" \
  --run-dir "./runs/manual_run" \
  --workers 4 \
  --pdf-workers 2 \
  --file-timeout 600 \
  --max-file-size-mb 100 \
  --max-rows 50000
```

Параметры:

- `--input-dir` - исходная папка с файлами. Обязательный параметр.
- `--run-dir` - папка, куда писать результаты запуска.
- `--include-list` - файл со списком относительных путей, если нужно обработать не всю папку.
- `--workers` - количество процессов для обычных файлов и повторного анализа `.txt`.
- `--pdf-workers` - отдельный лимит параллельной обработки PDF.
- `--file-timeout` - таймаут на один тяжелый файл в секундах. `0` отключает таймаут.
- `--max-file-size-mb` - максимальный размер файла.
- `--max-rows` - лимит строк для табличных файлов.
- `--no-ocr` - отключить OCR.

## Проверка установки

После установки можно проверить, что команды запуска доступны:

macOS/Linux:

```bash
python run_pipeline.py --help
python main.py --help
python reprocess_from_txt.py --help
```

Windows:

```powershell
python .\run_pipeline.py --help
python .\main.py --help
python .\reprocess_from_txt.py --help
```

## Частые проблемы

### `ModuleNotFoundError`

Обычно означает, что не активировано виртуальное окружение или не установлены зависимости.

macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### OCR не распознает русский текст

Проверьте, что установлен язык `rus`:

```bash
tesseract --list-langs
```

В выводе должны быть:

```text
eng
rus
```

### Видео не обрабатываются

Проверьте наличие `ffmpeg` и `ffprobe`:

```bash
ffmpeg -version
ffprobe -version
```

### Старые `.doc` файлы не читаются

На macOS проект пробует использовать системный `textutil`.

На Windows и Linux для старых `.doc` может потребоваться дополнительная настройка `textract` или конвертация `.doc` в `.docx` перед запуском.


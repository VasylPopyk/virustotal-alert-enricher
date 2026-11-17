# VirusTotal Alert Enricher

A lightweight Python tool for SOC and SOAR alert enrichment. It takes file hashes (MD5, SHA-1, SHA-256) from SIEM or EDR alerts, queries the VirusTotal API v3, handles HTTP 429 rate limits, and returns a verdict based on engine thresholds.

Легкий Python-інструмент для збагачення алертів у SOC та SOAR. Він бере хеші файлів (MD5, SHA-1, SHA-256) з алертів SIEM або EDR, запитує VirusTotal API v3, обробляє обмеження HTTP 429 і повертає вердикт на основі порогів двигунів антивірусів.

> Learning project, part of a SOC/SIEM study plan (Day 16: REST API, VirusTotal).
> Навчальний проєкт, частина плану з SOC/SIEM (День 16: REST API, VirusTotal).

---

## English

### Features

- **Local hash validation.** MD5, SHA-1, and SHA-256 are checked with a regular expression before any API request, so invalid input does not use your quota.
- **Rate limit handling.** On HTTP 429, the script reads the `Retry-After` header (or waits 60 seconds if it is missing), then retries. Alerts are not dropped.
- **Retry on server errors.** HTTP 5xx and network errors are retried with exponential backoff.
- **Verdict classification.** Each hash gets `MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN` (HTTP 404), or `ERROR`. The verdict uses engine consensus, not a single detection.
- **Structured output.** Results are returned as a dataclass that converts to a dictionary, ready for JSON, Wazuh, Splunk, Shuffle, or TheHive.
- **Secrets from the environment.** The API key is read from `VT_API_KEY` and is never stored in the code.

### Requirements

- Python 3.8 or newer
- A VirusTotal API key (free public key is enough for this tool)
- Internet access to `www.virustotal.com`

### Installation

```bash
git clone https://github.com/<your-username>/virustotal-alert-enricher.git
cd virustotal-alert-enricher
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install requests
```

### Configuration

Set the API key as an environment variable. Do not put it in the source code.

```bash
export VT_API_KEY="your_64_character_api_key"          # Linux/macOS
```

```powershell
$env:VT_API_KEY = "your_64_character_api_key"          # Windows PowerShell
```

### Usage

Run the script:

```bash
python3 script.py
```

The current script checks five built-in test hashes: three EICAR test-file hashes (MD5, SHA-1, SHA-256) and two non-existent hashes. To enrich your own alerts, replace the `alert_hashes` list in the `__main__` block, or import the client in your own code:

```python
import os
from script import VirusTotalClient

client = VirusTotalClient(api_key=os.environ["VT_API_KEY"])
result = client.enrich_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
print(result.verdict, result.malicious_count)
```

### Example output

The values below are an example. Real numbers depend on the current VirusTotal data.

```python
{
    "hash_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "verdict": "MALICIOUS",
    "malicious_count": 60,
    "suspicious_count": 0,
    "total_engines": 72,
    "threat_label": "eicar",
    "file_name": "eicar.com",
    "vt_link": "https://www.virustotal.com/gui/file/275a021b...",
    "error": None
}
```

### Verdict logic

| Verdict | Condition | Meaning for the analyst |
|---|---|---|
| `MALICIOUS` | `malicious >= 3`, or `malicious >= 1` and `reputation < -10` | Confirmed threat. Escalate or contain. |
| `SUSPICIOUS` | `malicious` is 1 or 2, or `suspicious >= 2` | Possible false positive or packed file. Manual triage needed. |
| `CLEAN` | No malicious or suspicious detections | Known benign across the scanning engines. |
| `UNKNOWN` | HTTP 404 | Hash is not in VirusTotal. Consider sandbox analysis. |
| `ERROR` | Invalid format, authentication failure, or retries exhausted | Check the `error` field and the log. |

### Project structure

```text
virustotal-alert-enricher/
├── script.py      # VirusTotal client, verdict logic, entry point
└── README.md
```

### Security notes

- **Hash lookups are not private.** Querying a hash on VirusTotal sends that hash to VirusTotal, and it becomes visible in their data. This is generally acceptable for common malware. For hashes of internal or targeted files, check your policy first. The tool itself does not upload files.
- **Keep the API key secret.** Never commit it. If it appeared in a screenshot, chat, or repository, revoke it in your VirusTotal account and create a new one.
- **Public API limits.** The free public key allows about 4 requests per minute. Enriching many alerts takes time because of the built-in waits.

### Limitations

- The public API is rate limited, so large batches are slow.
- The `alert_hashes` list in `__main__` is a demo list, not a connection to a real SIEM.
- No unit tests yet. Planned: tests with mocked HTTP responses for 200, 404, 429, and 5xx.

### Roadmap

- Read alerts from a file or from Wazuh and enrich them in a batch.
- Write results to a JSON report and a CSV summary.
- Add unit tests for verdict logic and rate limit handling.

### License and legal notice

For educational and defensive security use. Use the VirusTotal API in line with its terms of service.

---

## Українська

### Можливості

- **Локальна перевірка хешів.** MD5, SHA-1 і SHA-256 перевіряються регулярним виразом до будь-якого запиту, тож некоректний вхід не витрачає квоту.
- **Обробка обмеження частоти (HTTP 429).** Скрипт читає заголовок `Retry-After` (або чекає 60 секунд, якщо його немає) і повторює запит. Алерти не втрачаються.
- **Повтори при помилках сервера.** Помилки 5xx і мережеві помилки повторюються з експоненційною паузою.
- **Класифікація вердиктів.** Кожен хеш отримує `MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN` (HTTP 404) або `ERROR`. Вердикт базується на згоді кількох двигунів, а не на одному спрацюванні.
- **Структурований результат.** Результат повертається як dataclass, який перетворюється на словник і готовий для JSON, Wazuh, Splunk, Shuffle або TheHive.
- **Секрети зі середовища.** API-ключ береться зі змінної `VT_API_KEY` і не зберігається в коді.

### Вимоги

- Python 3.8 або новіший
- API-ключ VirusTotal (для цього інструмента достатньо безкоштовного публічного ключа)
- Доступ до інтернету на `www.virustotal.com`

### Встановлення

```bash
git clone https://github.com/<your-username>/virustotal-alert-enricher.git
cd virustotal-alert-enricher
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install requests
```

### Налаштування

Передайте API-ключ через змінну середовища. Не вписуйте його в код.

```bash
export VT_API_KEY="ваш_64_символьний_ключ"             # Linux/macOS
```

```powershell
$env:VT_API_KEY = "ваш_64_символьний_ключ"             # Windows PowerShell
```

### Використання

Запуск скрипта:

```bash
python3 script.py
```

Поточний скрипт перевіряє п'ять тестових хешів: три хеші тестового файлу EICAR (MD5, SHA-1, SHA-256) і два неіснуючі хеші. Щоб збагатити свої алерти, замініть список `alert_hashes` у блоці `__main__` або імпортуйте клієнт у свій код:

```python
import os
from script import VirusTotalClient

client = VirusTotalClient(api_key=os.environ["VT_API_KEY"])
result = client.enrich_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
print(result.verdict, result.malicious_count)
```

### Приклад результату

Значення нижче наведені як приклад. Реальні цифри залежать від поточних даних VirusTotal.

```python
{
    "hash_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "verdict": "MALICIOUS",
    "malicious_count": 60,
    "suspicious_count": 0,
    "total_engines": 72,
    "threat_label": "eicar",
    "file_name": "eicar.com",
    "vt_link": "https://www.virustotal.com/gui/file/275a021b...",
    "error": None
}
```

### Логіка вердиктів

| Вердикт | Умова | Що це означає для аналітика |
|---|---|---|
| `MALICIOUS` | `malicious >= 3`, або `malicious >= 1` і `reputation < -10` | Підтверджена загроза. Ескалація або ізоляція. |
| `SUSPICIOUS` | `malicious` дорівнює 1 або 2, або `suspicious >= 2` | Можливий False Positive або запакований файл. Потрібна ручна перевірка. |
| `CLEAN` | Немає детектувань malicious і suspicious | Безпечний за результатами двигунів. |
| `UNKNOWN` | HTTP 404 | Хеша немає в VirusTotal. Розгляньте аналіз у пісочниці. |
| `ERROR` | Невірний формат, помилка автентифікації або вичерпано повтори | Перевірте поле `error` і лог. |

### Структура проєкту

```text
virustotal-alert-enricher/
├── script.py      # клієнт VirusTotal, логіка вердиктів, точка входу
└── README.md
```

### Примітки з безпеки

- **Пошук хешів не є приватним.** Запит хеша до VirusTotal передає цей хеш сервісу, і він стає видимим у їхніх даних. Для поширеного шкідливого ПЗ це зазвичай прийнятно. Для хешів внутрішніх або цільових файлів спершу перевірте політику компанії. Сам інструмент файли не завантажує.
- **Тримайте API-ключ у секреті.** Ніколи не комітьте його. Якщо він потрапив на скріншот, у чат або в репозиторій, відкличте його в акаунті VirusTotal і створіть новий.
- **Обмеження публічного API.** Безкоштовний ключ дозволяє близько 4 запитів на хвилину. Збагачення багатьох алертів займає час через вбудовані паузи.

### Обмеження

- Публічний API має обмеження частоти, тож великі пакети обробляються повільно.
- Список `alert_hashes` у `__main__` є демонстраційним, це не підключення до реального SIEM.
- Модульних тестів поки немає. Заплановано: тести з підміненими HTTP-відповідями для кодів 200, 404, 429 і 5xx.

### План розвитку

- Читати алерти з файлу або з Wazuh і збагачувати їх пакетом.
- Записувати результати в JSON-звіт і CSV-підсумок.
- Додати модульні тести для логіки вердиктів і обробки 429.

### Ліцензія і застереження

Для навчальних цілей і захисту. Використовуйте API VirusTotal відповідно до його умов використання.
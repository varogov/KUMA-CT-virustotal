# Tracer.py — URL Enrichment Server with VirusTotal Integration

## 📌 Описание

`Tracer.py` — это простой TCP-сервер на Python, предназначенный для приёма строк с URL, извлечения и декодирования параметра `url=...`, и отправки его в [VirusTotal](https://virustotal.com) для анализа.

Ответы клиентов обогащаются данными из VT и отправляются обратно в формате `key=value|...`.

Основное предназначение обогащение событий в SIEM KUMA

---

## 🚀 Возможности

- Поддержка нескольких клиентов (через select)
- Интеграция с VirusTotal v3 API
- Подсчёт количества сработавших антивирусов
- Извлечение тегов, категорий, финального URL и других параметров
- Форматированный ответ в стиле KUMA-интеграции

---

## 📥 Установка

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

2. Вставьте ваш API-ключ от VirusTotal:
```python
VT_API_KEY = "ВАШ_КЛЮЧ"
```

---

## ⚙️ Запуск

```bash
python3 Tracer.py
```

Сервер будет слушать порт `16666`. Вы можете подключаться клиентом (`nc`, `telnet` или своим скриптом) и отправлять данные для проверки
Передавать в KUMA

---

## 📤 Пример входящего сообщения:

```
some_id|url=https%3A%2F%2Fevil.com|more_data
```

## 📥 Пример ответа:

```
Category=miniCT_URL_Decoder|MatchedIndicator=https%3A%2F%2Fevil.com|decodedURL=https://evil.com|VT_Result=5/97 engines flagged|Engines=Dr.Web,Sophos|Tags=phishing|ScanDate=2025-07-25|ResultTypes=malicious,phishing
LookupFinished
```

---

## 📁 Структура проекта

- `Tracer.py` — основной серверный скрипт
- `requirements.txt` — зависимости Python
- `README.md` — этот файл

---

## ✅ Совместимость

- Python 3.6+
- Linux, macOS, Windows (лучше Linux)

---

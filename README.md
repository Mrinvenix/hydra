<!--
    ╔══════════════════════════════════════════════════════════════════════╗
    ║  HYDRA — multi-source OSINT core · v5.1.0                            ║
    ║  Copyright (c) 2026 MrInvenix (@MrInvenix) — MIT                     ║
    ║  Repo:    https://github.com/MrInvenix/hydra                         ║
    ║  Channel: https://t.me/info_by_invenix                               ║
    ║  Signature: hydra::v5::MrInvenix::2026                               ║
    ║  Fingerprint: 7f3a9c2e-MrInvenix-2026-hydra                          ║
    ║                                                                      ║
    ║  Do not remove this notice. If you fork — keep the original link.   ║
    ╚══════════════════════════════════════════════════════════════════════╝
-->

# ⚡ HYDRA

<!-- HYDRA-README-MARKER :: MrInvenix :: 2026 :: do-not-strip -->

<div align="center">

**multi-source OSINT core** · `v5.1.0`

*by [@MrInvenix](https://t.me/info_by_invenix)*

**Channel:** [t.me/info_by_invenix](https://t.me/info_by_invenix) · **Repo:** [github.com/MrInvenix/hydra](https://github.com/MrInvenix/hydra)

`passive by default` · `active behind flags` · `MIT`

</div>

---

## 📖 Что это

HYDRA — асинхронное ядро OSINT-разведки. Даёшь один ник, email, телефон, ФИО
или домен — она параллельно опрашивает 200+ источников, находит совпадения
между ними и отдаёт результат в 6 форматах:

```
console · HTML · JSON · CSV · Markdown · graph (mermaid)
```

Passive по умолчанию — просто открывает публичные страницы. Активные техники
(recovery-формы, dorks) только за явными флагами и с прокси.

<!-- WATERMARK :: author=MrInvenix :: sig=hydra::v5::MrInvenix::2026 -->

---

## ⚠️ Важно: где запускать

| платформа | скорость | стабильность | ограничения |
|---|---|---|---|
| 💻 **ПК (Windows / macOS / Linux)** | ⚡⚡⚡ полная | ✅ стабильно | нет |
| 📱 **телефон (Android через Termux)** | 🐢 в 3–5 раз медленнее | 🟡 иногда падает | ограничения Android |
| 📱 **телефон (без Termux)** | ❌ нельзя | — | нет Python |

> **На ПК он работает лучше.** Больше параллельных задач, никаких
> ограничений Android на сеть и файлы, все 200+ чекеров летят одновременно.
> На телефоне через Termux — работает, но медленнее и капризнее.

---

## 🖥️ Установка и запуск на ПК

**Работает на:** Windows 10/11, macOS 12+, Linux (Ubuntu/Debian/Arch).

### Windows

**1.** Поставь Python 3.11+ → [python.org/downloads](https://www.python.org/downloads/)  
При установке отметь ✅ **«Add Python to PATH»**

**2.** Открой **PowerShell** (Win + X → «Терминал» / «PowerShell»)

**3.** Перейди в папку с HYDRA:
```powershell
cd C:\путь\до\HYDRA
```

**4.** Поставь зависимости:
```powershell
pip install -r requirements.txt
```

**5.** Запусти:
```powershell
python hydra.py scan torvalds
```

### macOS / Linux

**1.** Проверь Python:
```bash
python3 --version
```
Если меньше 3.11 — обнови через `brew install python@3.11` (macOS) или
`sudo apt install python3.11` (Ubuntu).

**2.** Перейди в папку:
```bash
cd ~/путь/до/HYDRA
```

**3.** Зависимости:
```bash
pip3 install -r requirements.txt
```

**4.** Запуск:
```bash
python3 hydra.py scan torvalds
```

---

## 📱 Установка и запуск на телефоне (Android)

**iPhone не поддерживается** — на iOS нет Termux, скрипт не запустится.

### Способ 1 — Termux (правильный, но дольше)

**1.** Поставь **Termux** из **F-Droid** (не из Play Store — там версия устарела)  
Ссылка: [f-droid.org/packages/com.termux](https://f-droid.org/packages/com.termux/)

**2.** Открой Termux, введи по одной строке:

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install aiohttp aiohttp-socks aiosqlite phonenumbers rich pyyaml pydantic pydantic-settings
```

**3.** Дай доступ к файлам:
```bash
termux-setup-storage
```
Появится окно Android → разреши доступ.

**4.** Перейди в папку с HYDRA:
```bash
cd /storage/emulated/0/HYDRA
```

**5.** Запусти:
```bash
python hydra.py scan torvalds
```

### Способ 2 — Acode (только посмотреть код)

Если хочешь просто **открыть и почитать** `hydra.py` на телефоне — поставь
[Acode](https://play.google.com/store/apps/details?id=com.foxdebug.acode) из
Play Store. Открой файл, читай с подсветкой синтаксиса.

**Запустить из Acode нельзя** — нужен Termux.

<!-- WATERMARK :: method=install :: author=MrInvenix :: @MrInvenix -->

---

## 🚀 Первый запуск — проверка что всё работает

```bash
python hydra.py --smoke
```

Это самопроверка: HYDRA стучится в безопасные цели по каждому чекеру и
показывает, что живо, что сдохло, что блокируется. Занимает ~30 секунд.

Ожидаемый вывод — таблица с состояниями `OK` / `BLOCKED` / `DEAD`.

---

## 🎯 Примеры команд

```bash
# username по 200+ сайтам
python hydra.py scan torvalds

# email
python hydra.py scan user@example.com

# телефон
python hydra.py scan +14155552671

# ФИО по судебным реестрам РФ
python hydra.py --fio "Иванов Иван"

# домен (WHOIS / RDAP)
python hydra.py scan example.com

# паранойя-режим: jitter + без кэша
python hydra.py scan torvalds --jitter 0.3 --no-cache

# удалить кэш после прогона
python hydra.py scan torvalds --wipe
```

После прогона в папке появится 6 отчётов:

```
hydra_report.json      ← полный дамп
hydra_report.html      ← открыть в браузере
hydra_report.csv       ← таблица
hydra_report.md        ← markdown
hydra_report.graph.json ← для визуализации
hydra_report.mmd       ← mermaid-диаграмма
```

Открой **`hydra_report.html`** в браузере — там всё в человеческом виде.

---

## 🔧 Полезные флаги

| флаг | что делает |
|---|---|
| `--smoke` | самопроверка всех чекеров |
| `--jitter 0.3` | рандомная задержка до 300 мс перед запросом |
| `--no-cache` | не писать кэш на диск |
| `--wipe` | удалить кэш после прогона |
| `--concurrency 50` | больше параллельных задач (ПК) |
| `--no-wmn` | не грузить 200+ чекеров WhatsMyName |
| `--branded` | подпись в сети (только для демо) |

Активные (требуют прокси):
| флаг | что делает |
|---|---|
| `--mode active --allow-active` | включить активные техники |
| `--dorks` | поиск через DuckDuckGo |
| `--recovery-forms` | recovery-формы сервисов |
| `--browser` | JS-фолбэк через Playwright |

---

## 🔑 Секреты (опционально)

Нужны только для HIBP и EmailRep. Без них HYDRA работает — просто не
использует эти два источника.

**ПК (Windows PowerShell):**
```powershell
$env:HYDRA_HIBP_KEY="xxxx"
```

**ПК (macOS / Linux) и Termux:**
```bash
export HYDRA_HIBP_KEY="xxxx"
export HYDRA_EMAILREP_KEY="xxxx"
```

---

## 🛠 Если что-то не работает

**`python: command not found`**  
→ Python не в PATH. Переустанови с галочкой «Add to PATH».

**`ModuleNotFoundError: No module named 'aiohttp'`**  
→ Зависимости не поставились. Повтори `pip install -r requirements.txt`.

**На телефоне `Permission denied`**  
→ В Termux: `termux-setup-storage` и разреши доступ.

**Всё летит в `BLOCKED` / `CAPTCHA`**  
→ Норма для пассивного прогона. Часть сервисов режет анонимные запросы.
Это ожидаемое поведение, не баг.

**Скрипт запустился и ничего не вывел**  
→ Он работает. Дождись окончания — прогресс-бар покажет статус.

---

## 🧭 Два режима — что выбрать

```
┌─────────────────────────────────────────────────────────┐
│  PASSIVE (по умолчанию)                                 │
│  ✅ публичные API и страницы                            │
│  ✅ не палимся                                          │
│  ✅ работает без прокси                                 │
│  ⚠️  часть источников отдаёт мало                       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  ACTIVE (только с --mode active --allow-active)         │
│  🔥 recovery-формы, dorks, JS-фолбэк                    │
│  🔥 требует прокси-пул                                  │
│  🔥 юридическая ответственность на операторе             │
│  ⚠️  152-ФЗ, ст. 272 УК РФ, GDPR, CFAA                  │
└─────────────────────────────────────────────────────────┘
```

Начинай с **passive**. Актив — только если знаешь зачем и есть правовое
основание.

---

## 📌 Итог

```
1. Поставь Python 3.11+ (ПК) или Termux (телефон)
2. pip install -r requirements.txt
3. python hydra.py --smoke
4. python hydra.py scan <цель>
5. Открой hydra_report.html
```

**На ПК быстрее и стабильнее.** На телефоне — работает, но медленнее.

---

<!-- WATERMARK :: signature=hydra::v5::MrInvenix::2026 :: fingerprint=7f3a9c2e-MrInvenix-2026-hydra -->

<div align="center">

**HYDRA v5.1.0**

*by [@MrInvenix](https://t.me/info_by_invenix)*

**Channel:** [t.me/info_by_invenix](https://t.me/info_by_invenix)  
**Repo:** [github.com/MrInvenix/hydra](https://github.com/MrInvenix/hydra)

© 2026 MrInvenix · MIT License

*If you fork — keep the original copyright and links.*

<sub>`HYDRA_SIGNATURE = hydra::v5::MrInvenix::2026`</sub>  
<sub>`HYDRA_FINGERPRINT = 7f3a9c2e-MrInvenix-2026-hydra`</sub>

</div>

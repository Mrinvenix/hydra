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

**Два интерфейса:**
- **CLI** — терминал, скрипты, автоматизация
- **Web UI** — тёмный интерфейс в браузере с прогресс-баром (опционально)

<!-- WATERMARK :: author=MrInvenix :: sig=hydra::v5::MrInvenix::2026 -->

---

## ⚡ Быстрая установка (TL;DR)

```bash
git clone https://github.com/MrInvenix/hydra.git
cd hydra
pip install -r requirements.txt
python hydra.py --smoke
```

Или скачай ZIP: **Code → Download ZIP** на странице репо → распакуй → `pip install -r requirements.txt`.

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

**2.** Скачай HYDRA: **Code → Download ZIP** → распакуй, или `git clone`.

**3.** Открой **PowerShell** (Win + X → «Терминал» / «PowerShell»)

**4.** Перейди в папку с HYDRA:
```powershell
cd C:\путь\до\hydra
```

**5.** Поставь зависимости:
```powershell
pip install -r requirements.txt
```

**6.** Запусти (CLI):
```powershell
python hydra.py scan torvalds
```

Или веб-интерфейс:
```powershell
python app.py
```
→ открой `http://127.0.0.1:5000` в браузере.

### macOS / Linux

**1.** Проверь Python:
```bash
python3 --version
```
Если меньше 3.11 — обнови через `brew install python@3.11` (macOS) или
`sudo apt install python3.11` (Ubuntu).

**2.** Скачай HYDRA и перейди в папку:
```bash
git clone https://github.com/MrInvenix/hydra.git
cd hydra
```

**3.** Зависимости:
```bash
pip3 install -r requirements.txt
```

**4.** Запуск (CLI):
```bash
python3 hydra.py scan torvalds
```

Или веб-интерфейс:
```bash
python3 app.py
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
pip install -r requirements.txt
```

**3.** Дай доступ к файлам:
```bash
termux-setup-storage
```
Появится окно Android → разреши доступ.

**4.** Перейди в папку с HYDRA:
```bash
cd /storage/emulated/0/hydra
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

## 🌐 Веб-интерфейс (опционально)

Если не хочешь работать в терминале — есть тёмный веб-UI с прогресс-баром,
логом в реальном времени и таблицей результатов.

### Запуск

```bash
pip install flask
python app.py
```

Открой в браузере:

```
http://127.0.0.1:5000
```

### Что умеет

- Поле **target** — username / email / phone / ФИО / domain
- Переключатель **passive / active**
- **Прогресс-бар** — заполняется по мере выполнения
- **Лог** — каждая строка = один чекер (зелёный = найден, серый = нет)
- **Таблица hits** — source, target, confidence, status, evidence, url

### Оформление

Тёмная тема: чёрный фон, серые панели, тёмно-зелёный акцент. Всё читаемо
даже при ярком свете. Работает на телефоне и ПК.

### С телефона на ПК-сервер

Если ПК и телефон в одной Wi-Fi сети — можно рулить сканом с телефона,
а работать всё будет на ПК (быстрее).

**1.** На ПК в `app.py` поменяй:
```python
HOST = "127.0.0.1"    →    HOST = "0.0.0.0"
```

**2.** Запусти `python app.py`.

**3.** Узнай IP ПК:
- Windows: `ipconfig` → смотри **IPv4**
- macOS / Linux: `ifconfig` → смотри `inet` (обычно `192.168.x.x`)

**4.** На телефоне в браузере:
```
http://192.168.1.XX:5000
```

> ⚠️ `0.0.0.0` открывает доступ **всем в той же сети**. Только для домашнего
> Wi-Fi. В общественной сети (кафе, отель) оставляй `127.0.0.1`.

### Файлы веб-интерфейса

```
app.py                  ← Flask-сервер
templates/index.html    ← HTML-страница UI
static/style.css        ← оформление
```

---

## 🚀 Первый запуск — проверка что всё работает

```bash
python hydra.py --smoke
```

Это самопроверка: HYDRA стучится в безопасные цели по каждому чекеру и
показывает, что живо, что сдохло, что блокируется. Занимает ~30 секунд.

Ожидаемый вывод — таблица с состояниями `OK` / `BLOCKED` / `DEAD`.

---

## 🎯 Примеры команд (CLI)

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

Или скопируй `.env.example` → `.env` и заполни.

---

## 🛠 Если что-то не работает

**`python: command not found`**  
→ Python не в PATH. Переустанови с галочкой «Add to PATH».

**`ModuleNotFoundError: No module named 'aiohttp'`**  
→ Зависимости не поставились. Повтори `pip install -r requirements.txt`.

**`ModuleNotFoundError: No module named 'flask'`**  
→ Не поставился flask. `pip install flask`.

**Веб-UI не открывается (`http://127.0.0.1:5000`)**  
→ Проверь, что `python app.py` запущен и не упал. Смотри сообщения в терминале.

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

**CLI:**
```
1. git clone https://github.com/MrInvenix/hydra.git
2. cd hydra
3. pip install -r requirements.txt
4. python hydra.py --smoke
5. python hydra.py scan <цель>
```

**Web UI:**
```
1. pip install flask
2. python app.py
3. Открой http://127.0.0.1:5000
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

</div><!--
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

# Changelog

All notable changes to HYDRA are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/),
versioning follows [SemVer](https://semver.org/).

## [5.1.0] — 2026

### Added
- **Circuit breaker** в `HostLimiter`: хост с N×429/403/503 подряд уходит в карантин на 5 минут, не долбим
- Флаг `--jitter N` — рандомная задержка перед запросом (анти-паттерн для машинного детекта)
- Флаг `--no-cache` — полностью отключить SQLite-кэш
- Флаг `--wipe` — удалить кэш-файлы после прогона
- Флаг `--branded` — opt-in подпись в сети (branded UA + X-Hydra-*)
- `Cache.wipe()` — метод удаления кэша с диска
- `Cache.__init__` параметр `enabled` — глобальный выключатель кэша
- `HostLimiter.is_tripped()` / `record_failure()` / `record_success()` — API circuit breaker
- Конфиг-поля `EngineCfg.jitter`, `EngineCfg.breaker_threshold`, `EngineCfg.breaker_cooldown`
- `_BRANDED_UA` вынесена из `UA_POOL` отдельной константой
- `EngineCfg` расширен параметрами безопасности

### Changed
- **OPSEC-дефолты**: в сети по умолчанию только обычный браузерный UA, никаких `X-Hydra-*`
- **UA фиксирован на сессию** (`self._session_ua`) — запросы не коррелируют по User-Agent
- `headers()` получил параметры `branded: bool = False` и `ua: str | None`
- Branded UA больше **не в пуле** — уходит только с `--branded`
- `X-Hydra-*` заголовки жёстко вычищаются при `branded=False` — страховка на случай пролеза
- `Referrer-Policy: no-referrer` добавлен в каждый запрос
- `OSINTEngine.__init__` принимает `branded`, `jitter`, `breaker_threshold`, `breaker_cooldown`
- `_run_one` проверяет `limiter.is_tripped()` перед запросом — skip с пометкой
- `_run_one` фиксирует исход хоста (`record_failure`/`record_success`)
- `cmd_scan` и `cmd_smoke` прокидывают security-флаги в engine
- `cmd_scan` в конце удаляет кэш при `--wipe`

### Security
- **Устранена утечка авторства в сеть**: раньше `X-Hydra-*` заголовки уходили на каждый сайт, где видел их любой сисадмин и Cloudflare — теперь только по явному флагу
- **Branded UA убран из дефолтного пула** — 1 из 6 запросов больше не палит себя
- **Referrer-Policy: no-referrer** — источник перехода не утекает
- **Фиксация UA на сессию** — защита от корреляции запросов по рандомному User-Agent
- **Circuit breaker** — забаненные хосты не долбятся, экономия прокси и снижение детектируемости
- **Jitter** — паттерн запросов перестаёт быть машинно-регулярным
- **--no-cache / --wipe** — возможность не оставлять следов на диске

### Fixed
- `Cache.get` / `Cache.put` корректно работают при `enabled=False` (не открывают SQLite)
- `Cache.should_cache` учитывает флаг `enabled`

### Documentation
- Обновлена шапка `hydra.py` — OPSEC-дефолты v5.1 описаны в блоке комментариев
- Уточнено: `X-Hydra-*` уходят в сеть только с `--branded`
- Watermark-слой явно разделён: **файл — громко, сеть — тихо**

## [5.0.0] — 2026

### Added
- Watermark-слой во всех отчётах, graph, HTTP-заголовках, console
- `HYDRA_SIGNATURE` / `HYDRA_FINGERPRINT` — авторский маркер
- Graph-watermark node `hydra:watermark`
- JSON-отчёт с `_wm_stamp()` в корне
- MIT + copyright + ссылки в LICENSE и README
- `.gitignore`, `.env.example`, `pyproject.toml`, `hydra.yaml`
- Тесты `tests/test_core.py` + `tests/test_cache.py`
- `__main__.py` entrypoint для `python -m hydra` и `hydra`

### Changed
- `Finding._origin` — скрытый маркер в каждом результате
- `meta._generator` / `_author` / `_channel` / `_signature` в каждом Finding
- HTML / CSV / MD / graph / mermaid — с подписью
- Модульная структура: `models.py`, `utils.py`, `config.py`, `core.py`, `cli.py`, `checkers/`
- `HostLimiter.acquire` — sleep вне лока, локи через `defaultdict`
- `_eligible` — ФИО больше не уходит в username-чекеры
- `EmailRegistered` — узкие маркеры блокировки вместо `"captcha" in body`
- `Cache.put` — не кэширует `dead` / `skipped` / `error`
- `ssl=False` убран из `TCPConnector` — TLS-проверка включена
- `prog.console.log` → `prog.log` — не рвёт перерисовку

### Fixed
- `evaluate_html` не перетирает `target` — корреляция работает после JS-фолбэка
- `proxy_required` читается движком — скип без сетевого шума
- HTML-escape в `render_html` — XSS на себя через `evidence` / `url`
- `EmailRep` / `HIBP` / `DomainRecon` — pre-check `body[:1] in "{[` перед `json.loads`

### Removed
- Branded UA из дефолтного пула (перенесён в `_BRANDED_UA`, используется только с `--branded`)

## [Unreleased]

### Planned
- `check_update()` — проверка новой версии через GitHub Releases API
- Флаг `--check-update` — отдельный режим проверки
- Авто-уведомление об апдейте в конце прогона
- Chunked submit через `asyncio.Queue` — стабильная память на 1000+ задач
- Веса в корреляции + транзитивная связка (A↔B через email, B↔C через телефон → A и C связаны)
- GitHub Actions CI (`.github/workflows/test.yml`)
# language: Python 3.11+, file: hydra.py
# target: cross-platform
# deps: aiohttp, aiohttp_socks, phonenumbers, rich, aiosqlite, pydantic, pydantic-settings, pyyaml
# opt:  playwright (для JS-фолбэка)
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                                                                          ║
# ║    ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗                              ║
# ║    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗                             ║
# ║    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║                             ║
# ║    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║                             ║
# ║    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║                             ║
# ║    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                             ║
# ║                                                                          ║
# ║    HYDRA — multi-source OSINT core · v5.1                                ║
# ║    many heads, one target                                                ║
# ║                                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# ────────────────────────────────────────────────────────────────────────────
#  Copyright (c) 2026 MrInvenix (@MrInvenix)
#  Licensed under the MIT License
#  Original repository: https://github.com/MrInvenix/hydra
#  Channel:             https://t.me/info_by_invenix
#
#  HYDRA_SIGNATURE:     hydra::v5::MrInvenix::2026
#  HYDRA_FINGERPRINT:   7f3a9c2e-MrInvenix-2026-hydra
#
#  Do not remove this notice. If you fork — keep the original link.
# ────────────────────────────────────────────────────────────────────────────
#
# ============================================================================
# ЧТО БЬЁТ И ГДЕ БЬЁТ (прочти перед --mode active)
# ----------------------------------------------------------------------------
# passive: только публичные страницы/API, которые сами отдают данные анонимно.
#          Никаких форм, никаких восстановлений пароля, никаких dorks.
# active:  recovery-формы (Holehe-механика), dorks через поисковики,
#          опционально Playwright. Это уже не пассивный сбор.
#
# В РФ: 152-ФЗ (персональные данные) + ст. 272 УК (неправомерный доступ).
# Recovery-формы и dorks к чужим сервисам могут трактоваться как попытка
# доступа к защищённой информации. Ответственность — на операторе.
# Вне РФ: GDPR ст. 6 (правовое основание), CFAA в США, аналоги в ЕС.
#
# Секреты — только через env (HYDRA_HIBP_KEY, HYDRA_EMAILREP_KEY).
# Никогда не в CLI — не светятся в history/ps.
#
# OPSEC-дефолты (v5.1):
#   * обычный браузерный UA, X-Hydra-* вычищаются
#   * Referrer-Policy: no-referrer
#   * UA фиксирован на сессию — запросы не коррелируют по UA
#   * circuit breaker: хост с N×429 уходит в карантин на 5 минут
#   * --jitter N — рандомная задержка перед запросом (анти-паттерн)
#   * --no-cache / --wipe — не оставляем следов на диске
#   * --branded — включить подпись в сети (только свой сервер / демка)
# ============================================================================

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import random
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from email.utils import parsedate_to_datetime
from html import escape as html_escape
from pathlib import Path
from typing import Any, Iterable, Protocol
from urllib.parse import quote, urlparse

import aiohttp
import aiosqlite
from aiohttp_socks import ProxyConnector
import phonenumbers
from phonenumbers import geocoder, carrier, NumberParseException
from rich.console import Console
from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table


console = Console()


# ══════════════════════════════════════════════════════════════════════════
#  HYDRA · AUTHORSHIP + WATERMARK
#  Маркеры живут в отчётах, графе, mermaid, консоли, README, LICENSE.
#  В сеть по умолчанию НЕ уходят (OPSEC) — только флагом --branded.
# ══════════════════════════════════════════════════════════════════════════

HYDRA_VERSION     = "5.1.0"
HYDRA_AUTHOR      = "MrInvenix"
HYDRA_HANDLE      = "@MrInvenix"
HYDRA_REPO        = "https://github.com/MrInvenix/hydra"
HYDRA_CHANNEL     = "https://t.me/info_by_invenix"
HYDRA_SIGNATURE   = "hydra::v5::MrInvenix::2026"
HYDRA_FINGERPRINT = "7f3a9c2e-MrInvenix-2026-hydra"
HYDRA_COPYRIGHT   = "Copyright (c) 2026 MrInvenix (@MrInvenix) — MIT"


# ============================================================================
# ===========================  МОДЕЛЬ + УТИЛИТЫ  =============================
# ============================================================================

@dataclass
class Finding:
    source: str
    target: str
    found: bool
    url: str | None = None
    status: int | None = None
    evidence: str | None = None
    error: str | None = None
    elapsed_ms: int = 0
    meta: dict = field(default_factory=dict)
    confidence: str = "n/a"
    mode: str = "passive"
    from_cache: bool = False
    _origin: str = "hydra::MrInvenix::v5"


@dataclass(frozen=True)
class CheckerMeta:
    name: str
    kind: str
    mode: str
    proxy_required: bool = False
    needs_browser: bool = False
    no_network: bool = False
    tags: tuple[str, ...] = ()


class Checker(Protocol):
    name: str
    kind: str
    mode: str
    needs_browser: bool
    proxy_required: bool
    no_network: bool

    async def check(self, session: Any, target: str) -> Finding: ...
    def evaluate_html(self, body: str, code: int, url: str,
                      target: str) -> Finding: ...


# ── branded UA вынесен отдельно, в пуле его нет. Только под --branded ───
_BRANDED_UA = (
    f"Mozilla/5.0 (compatible; HYDRA/{HYDRA_VERSION}; "
    f"+{HYDRA_REPO}) {HYDRA_HANDLE}/{HYDRA_CHANNEL}"
)

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 "
    "Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]

BLOCK_MARKERS = (
    "cf-chl", "hcaptcha-challenge", "g-recaptcha-response",
    "just a moment", "checking your browser", "attention required",
)


def headers(extra: dict | None = None, branded: bool = False,
            ua: str | None = None) -> dict:
    """
    Собирает заголовки HTTP-запроса.

    branded=False (по умолчанию) — не палимся:
        обычный браузерный UA, никаких X-Hydra-* заголовков.
    branded=True — branded UA + X-Hydra-*:
        только для своего сервера, демки, тестов.
    ua=... — принудительный UA (ротация в рамках сессии).
    """
    h = {
        "User-Agent": ua or (_BRANDED_UA if branded else random.choice(UA_POOL)),
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8,ru;q=0.6",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Referrer-Policy": "no-referrer",
    }
    if branded:
        h["X-Hydra-Client"] = f"hydra-v{HYDRA_VERSION}"
        h["X-Hydra-Author"] = HYDRA_HANDLE
        h["X-Hydra-Repo"] = HYDRA_REPO
        h["X-Hydra-Channel"] = HYDRA_CHANNEL
    else:
        # страховка: вычищаем любые x-hydra*, если где-то пролезли
        for k in list(h.keys()):
            if k.lower().startswith("x-hydra"):
                del h[k]
    if extra:
        h.update(extra)
    return h


def looks_like_email(s: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", s))


def looks_like_domain(s: str) -> bool:
    return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", s, re.I))


def looks_like_phone(s: str) -> bool:
    return bool(re.fullmatch(r"\+?\d[\d\s\-()]{6,}", s))


def looks_like_fio(s: str) -> bool:
    parts = s.split()
    if len(parts) < 2 or len(parts) > 3:
        return False
    return all(re.fullmatch(r"[А-ЯЁ][а-яё\-]+", p) for p in parts)


def avatar_hash(url: str) -> str | None:
    if not url:
        return None
    return hashlib.sha1(url.encode()).hexdigest()[:16]


def is_blocked_html(body_head: str) -> bool:
    low = body_head.lower()
    return any(m in low for m in BLOCK_MARKERS)


def looks_like_json(body: str) -> bool:
    return body.lstrip()[:1] in ("{", "[")


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
        return max(0.0, when.timestamp() - time.time())
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════
#  HYDRA · watermark helpers
# ══════════════════════════════════════════════════════════════════════════

def _wm_line() -> str:
    return (f"HYDRA v{HYDRA_VERSION} · {HYDRA_HANDLE} · "
            f"{HYDRA_REPO} · {HYDRA_CHANNEL}")


def _wm_stamp() -> dict:
    return {
        "_generator": "hydra",
        "_version": HYDRA_VERSION,
        "_author": HYDRA_AUTHOR,
        "_handle": HYDRA_HANDLE,
        "_repo": HYDRA_REPO,
        "_channel": HYDRA_CHANNEL,
        "_signature": HYDRA_SIGNATURE,
        "_fingerprint": HYDRA_FINGERPRINT,
        "_copyright": HYDRA_COPYRIGHT,
    }


# ============================================================================
# ==============================  КОНФИГ  ====================================
# ============================================================================

try:
    import yaml
    from pydantic import BaseModel, Field
    from pydantic_settings import BaseSettings, SettingsConfigDict
    _HAS_PYDANTIC = True
except Exception:
    _HAS_PYDANTIC = False


if _HAS_PYDANTIC:
    class EngineCfg(BaseModel):
        concurrency: int = 25
        timeout: float = 12.0
        retries: int = 3
        max_retry_after: float = 60.0
        cache_ttl: int = 900
        cache_path: str = "osint_cache.db"
        mode: str = "passive"
        jitter: float = 0.0
        breaker_threshold: int = 5
        breaker_cooldown: float = 300.0

    class ProxyCfg(BaseModel):
        list: list[str] = Field(default_factory=list)
        rotate_every: int = 20

    class WMNCfg(BaseModel):
        enabled: bool = True
        categories: list[str] = ["social", "coding", "dating", "gaming"]
        limit: int = 200
        cache_path: str = "wmn_cache.json"
        refresh_days: int = 7

    class Secrets(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="HYDRA_", env_file=".env",
                                          extra="ignore")
        hibp_key: str | None = None
        emailrep_key: str | None = None
        proxy_url: str | None = None

    class Config(BaseModel):
        engine: EngineCfg = EngineCfg()
        proxy: ProxyCfg = ProxyCfg()
        wmn: WMNCfg = WMNCfg()
        checkers: dict[str, dict[str, Any]] = Field(default_factory=dict)
        allow_active: bool = False

        @classmethod
        def load(cls, path: str | Path | None) -> "Config":
            if path and Path(path).exists():
                raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            else:
                raw = {}
            return cls.model_validate(raw)
else:
    class _FallbackCfg:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    class EngineCfg(_FallbackCfg):
        concurrency = 25
        timeout = 12.0
        retries = 3
        max_retry_after = 60.0
        cache_ttl = 900
        cache_path = "osint_cache.db"
        mode = "passive"
        jitter = 0.0
        breaker_threshold = 5
        breaker_cooldown = 300.0

        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    class ProxyCfg(_FallbackCfg):
        list: list = []
        rotate_every = 20

    class WMNCfg(_FallbackCfg):
        enabled = True
        categories = ["social", "coding", "dating", "gaming"]
        limit = 200
        cache_path = "wmn_cache.json"
        refresh_days = 7

    class Secrets:
        def __init__(self):
            import os
            self.hibp_key = os.environ.get("HYDRA_HIBP_KEY")
            self.emailrep_key = os.environ.get("HYDRA_EMAILREP_KEY")
            self.proxy_url = os.environ.get("HYDRA_PROXY_URL")

    class Config:
        def __init__(self, engine=None, proxy=None, wmn=None, checkers=None,
                     allow_active=False):
            self.engine = engine or EngineCfg()
            self.proxy = proxy or ProxyCfg()
            self.wmn = wmn or WMNCfg()
            self.checkers = checkers or {}
            self.allow_active = allow_active

        @classmethod
        def load(cls, path):
            import yaml as _y
            raw = {}
            if path and Path(path).exists():
                raw = _y.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            return cls(
                engine=EngineCfg(**(raw.get("engine") or {})),
                proxy=ProxyCfg(**(raw.get("proxy") or {})),
                wmn=WMNCfg(**(raw.get("wmn") or {})),
                checkers=raw.get("checkers") or {},
                allow_active=raw.get("allow_active", False),
            )


# ============================================================================
# ============================  ПРОКСИ-ПУЛ  ==================================
# ============================================================================

class ProxyPool:
    def __init__(self, proxies: list[str], rotate_every: int = 20):
        self.proxies = proxies
        self.rotate_every = rotate_every
        self._idx = 0
        self._counter = 0
        self._lock = asyncio.Lock()

    @property
    def empty(self) -> bool:
        return not self.proxies

    async def current(self) -> str | None:
        if self.empty:
            return None
        async with self._lock:
            p = self.proxies[self._idx]
            self._counter += 1
            if self._counter >= self.rotate_every:
                self._counter = 0
                self._idx = (self._idx + 1) % len(self.proxies)
            return p

    async def force_rotate(self) -> None:
        if self.empty:
            return
        async with self._lock:
            self._counter = 0
            self._idx = (self._idx + 1) % len(self.proxies)


# ============================================================================
# =============================  RATE LIMIT  =================================
# ============================================================================

class HostLimiter:
    """
    Token bucket на хост + circuit breaker.
    Если хост отдал N×429/403/503 подряд — skip на cooldown, не долбим.
    """
    KNOWN_RPS: dict[str, float] = {
        "api.github.com": 1.0,
        "haveibeenpwned.com": 0.2,
        "emailrep.io": 0.5,
        "t.me": 2.0,
        "wa.me": 2.0,
        "sudact.ru": 0.5,
        "sudrf.ru": 0.5,
        "bankrot.fedresurs.ru": 0.3,
        "html.duckduckgo.com": 0.2,
        "vk.com": 1.0,
        "ok.ru": 1.0,
        "instagram.com": 0.5,
        "tiktok.com": 0.5,
    }

    def __init__(self, default_rps: float = 2.0, burst: int = 4,
                 breaker_threshold: int = 5,
                 breaker_cooldown: float = 300.0):
        self.default_rps = default_rps
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._breaker: dict[str, list] = {}
        self.breaker_threshold = breaker_threshold
        self.breaker_cooldown = breaker_cooldown

    def _rps(self, host: str) -> float:
        for k, v in self.KNOWN_RPS.items():
            if host.endswith(k):
                return v
        return self.default_rps

    def is_tripped(self, url: str) -> bool:
        host = urlparse(url).netloc
        entry = self._breaker.get(host)
        if not entry:
            return False
        fails, until = entry
        if fails >= self.breaker_threshold:
            if time.monotonic() < until:
                return True
            self._breaker.pop(host, None)
        return False

    def record_failure(self, url: str) -> None:
        host = urlparse(url).netloc
        entry = self._breaker.setdefault(host, [0, 0.0])
        entry[0] += 1
        if entry[0] >= self.breaker_threshold:
            entry[1] = time.monotonic() + self.breaker_cooldown

    def record_success(self, url: str) -> None:
        self._breaker.pop(urlparse(url).netloc, None)

    async def acquire(self, url: str) -> None:
        host = urlparse(url).netloc
        if not host:
            return
        rps = self._rps(host)
        while True:
            wait_for = 0.0
            async with self._locks[host]:
                tokens, last = self._buckets.get(
                    host, (float(self.burst), time.monotonic()))
                now = time.monotonic()
                tokens = min(self.burst, tokens + (now - last) * rps)
                if tokens < 1:
                    wait_for = (1 - tokens) / rps
                    self._buckets[host] = (tokens, now)
                else:
                    self._buckets[host] = (tokens - 1, now)
                    return
            await asyncio.sleep(wait_for)


# ============================================================================
# ================================  КЭШ  =====================================
# ============================================================================

class Cache:
    def __init__(self, path: str = "osint_cache.db", ttl: int = 900,
                 enabled: bool = True):
        self.path = path
        self.ttl = ttl
        self.enabled = enabled
        self._ready = False
        self._lock = asyncio.Lock()

    async def _init(self):
        if self._ready or not self.enabled:
            return
        async with self._lock:
            if self._ready:
                return
            async with aiosqlite.connect(self.path) as db:
                await db.execute("""CREATE TABLE IF NOT EXISTS cache(
                    source TEXT, target TEXT, ts INTEGER, payload TEXT,
                    PRIMARY KEY(source, target))""")
                await db.commit()
            self._ready = True

    async def get(self, source: str, target: str) -> Finding | None:
        if not self.enabled:
            return None
        await self._init()
        async with aiosqlite.connect(self.path) as db:
            async with db.execute(
                "SELECT ts, payload FROM cache WHERE source=? AND target=?",
                (source, target)) as cur:
                row = await cur.fetchone()
        if row and time.time() - row[0] < self.ttl:
            data = json.loads(row[1])
            data["from_cache"] = True
            return Finding(**data)
        return None

    def should_cache(self, f: Finding) -> bool:
        if not self.enabled:
            return False
        if f.meta.get("skipped") or f.meta.get("dead") or f.error:
            return False
        return True

    async def put(self, f: Finding) -> None:
        if not self.should_cache(f):
            return
        await self._init()
        d = asdict(f)
        d.pop("from_cache", None)
        async with aiosqlite.connect(self.path) as db:
            await db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                             (f.source, f.target, int(time.time()),
                              json.dumps(d, ensure_ascii=False)))
            await db.commit()

    def wipe(self) -> None:
        try:
            if Path(self.path).exists():
                Path(self.path).unlink()
        except Exception:
            pass


# ============================================================================
# =============================  SCORING + CORR  =============================
# ============================================================================

def score_finding(f: Finding, corroboration: int = 0) -> str:
    if f.error or not f.found:
        return "n/a"
    s = 0
    if f.status == 200:
        s += 1
    if f.meta.get("created_at") or f.meta.get("name") or f.meta.get("bio"):
        s += 1
    if f.meta.get("breaches"):
        s += 1
    if corroboration >= 2:
        s += 3
    elif corroboration == 1:
        s += 1
    if f.mode == "active":
        s += 1
    if s >= 5:
        return "high"
    if s >= 3:
        return "medium"
    return "low"


def correlate(findings: list[Finding]) -> dict:
    by_email: dict[str, set] = {}
    by_phone: dict[str, set] = {}
    by_avatar: dict[str, set] = {}
    by_name: dict[str, set] = {}

    for f in findings:
        if not f.found:
            continue
        for e in (f.meta.get("emails") or []):
            by_email.setdefault(e.lower(), set()).add(f.source)
        for p in (f.meta.get("phones") or []):
            by_phone.setdefault(p, set()).add(f.source)
        if h := f.meta.get("avatar_hash"):
            by_avatar.setdefault(h, set()).add(f.source)
        if n := f.meta.get("name"):
            by_name.setdefault(n.lower(), set()).add(f.source)

    return {
        "by_email":  {k: sorted(v) for k, v in by_email.items() if len(v) > 1},
        "by_phone":  {k: sorted(v) for k, v in by_phone.items() if len(v) > 1},
        "by_avatar": {k: sorted(v) for k, v in by_avatar.items() if len(v) > 1},
        "by_name":   {k: sorted(v) for k, v in by_name.items() if len(v) > 1},
    }


def health_report(findings: list[Finding]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in findings:
        h = out.setdefault(f.source, {
            "runs": 0, "hits": 0, "dead": 0, "captcha": 0,
            "errors": 0, "skipped": 0,
        })
        h["runs"] += 1
        if f.found:
            h["hits"] += 1
        if f.meta.get("dead"):
            h["dead"] += 1
        if f.meta.get("captcha") or f.meta.get("blocked"):
            h["captcha"] += 1
        if f.error:
            h["errors"] += 1
        if f.meta.get("skipped"):
            h["skipped"] += 1
    return out


# ============================================================================
# ================================  ГРАФ  ====================================
# ============================================================================

def to_graph(findings: list[Finding]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(nid, ntype, label):
        nodes.setdefault(nid, {"id": nid, "type": ntype, "label": label})

    add_node("hydra:watermark", "generator",
             f"HYDRA v{HYDRA_VERSION} · {HYDRA_HANDLE}")

    for f in findings:
        if not f.found:
            continue
        src_id = f"source:{f.source}"
        tgt_id = f"target:{f.target}"
        add_node(src_id, "source", f.source)
        add_node(tgt_id, "target", f.target)
        edges.append({"from": src_id, "to": "hydra:watermark",
                      "kind": "generated_by"})
        edges.append({"from": src_id, "to": tgt_id, "kind": "found",
                      "confidence": f.confidence})
        for e in (f.meta.get("emails") or []):
            nid = f"email:{e.lower()}"
            add_node(nid, "email", e)
            edges.append({"from": tgt_id, "to": nid, "kind": "has_email"})
        for p in (f.meta.get("phones") or []):
            nid = f"phone:{p}"
            add_node(nid, "phone", p)
            edges.append({"from": tgt_id, "to": nid, "kind": "has_phone"})
        if h := f.meta.get("avatar_hash"):
            nid = f"avatar:{h}"
            add_node(nid, "avatar", h)
            edges.append({"from": tgt_id, "to": nid, "kind": "has_avatar"})

    return {**_wm_stamp(), "nodes": list(nodes.values()), "edges": edges}


def to_mermaid(graph: dict) -> str:
    def safe(s):
        return re.sub(r"[^A-Za-z0-9_]", "_", s)
    lines = [
        f"%% {_wm_line()}",
        f"%% {HYDRA_COPYRIGHT}",
        f"%% signature={HYDRA_SIGNATURE}",
        "graph LR",
    ]
    for n in graph["nodes"]:
        lines.append(f'  {safe(n["id"])}["{n["label"]}"]')
    for e in graph["edges"]:
        lines.append(f'  {safe(e["from"])} -->|{e["kind"]}| {safe(e["to"])}')
    return "\n".join(lines)


def export_graph(findings: list[Finding], json_path: str,
                 mmd_path: str | None = None) -> None:
    g = to_graph(findings)
    Path(json_path).write_text(json.dumps(g, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    if mmd_path:
        Path(mmd_path).write_text(to_mermaid(g), encoding="utf-8")


# ============================================================================
# ===========================  PLUGIN REGISTRY  ==============================
# ============================================================================

class _DisabledChecker:
    def __init__(self, meta: CheckerMeta, reason: str):
        self.name = meta.name
        self.kind = meta.kind
        self.mode = meta.mode
        self.needs_browser = meta.needs_browser
        self.proxy_required = meta.proxy_required
        self.no_network = True
        self._reason = reason

    async def check(self, session, target):
        return Finding(source=self.name, target=target, found=False,
                       error=f"disabled: {self._reason}",
                       meta={"skipped": True}, mode=self.mode)

    def evaluate_html(self, body, code, url, target):
        return Finding(source=self.name, target=target, found=False,
                       meta={"skipped": True})


# ============================================================================
# ==============================  ЧЕКЕРЫ  ====================================
# ============================================================================

WMN_URL = ("https://raw.githubusercontent.com/WebBreacher/"
           "WhatsMyName/main/wmn-data.json")


class WMNChecker:
    kind = "username"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False

    def __init__(self, name: str, uri_check: str, e_string: str = "",
                 m_string: str = "", e_code: int = 200, m_code: int = 404):
        self.name = name
        self.uri_check = uri_check
        self.e_string = e_string
        self.m_string = m_string
        self.e_code = e_code
        self.m_code = m_code
        self.url_tpl = uri_check.replace("{account}", "{u}")
        self.url_hint = uri_check.format(account="x")

    def _evaluate(self, body: str, code: int, url: str):
        if self.m_string and self.m_string in body:
            return False, None
        if self.e_string and self.e_string in body:
            return True, body[:200].replace("\n", " ")
        found = (code == self.e_code)
        return found, (body[:200].replace("\n", " ") if found else None)

    async def check(self, session, target: str) -> Finding:
        url = self.uri_check.format(account=quote(target))
        try:
            async with session.get(url, allow_redirects=True) as r:
                body = await r.text(errors="ignore")
                found, ev = self._evaluate(body, r.status, url)
                return Finding(source=self.name, target=target, found=found,
                               url=url, status=r.status, evidence=ev,
                               meta={"retry_after": r.headers.get("Retry-After"),
                                     **_wm_stamp()})
        except Exception as e:
            return Finding(source=self.name, target=target, found=False,
                           url=url, error=str(e), meta=_wm_stamp())

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev = self._evaluate(body, code, url)
        return Finding(source=self.name, target=target, found=found, url=url,
                       status=code, evidence=ev, meta=_wm_stamp())


async def load_wmn(cfg: WMNCfg) -> tuple[list[WMNChecker], dict]:
    p = Path(cfg.cache_path)
    data = None
    stale = True
    fetched_at = 0

    if p.exists():
        try:
            cached = json.loads(p.read_text(encoding="utf-8"))
            fetched_at = cached.get("_fetched_at", 0)
            age = time.time() - fetched_at
            stale = age > cfg.refresh_days * 86400
            data = cached
        except Exception:
            data = None

    if data is None or stale:
        try:
            async with aiohttp.ClientSession(headers=headers()) as s:
                async with s.get(WMN_URL) as r:
                    fresh = await r.json()
            fresh["_fetched_at"] = int(time.time())
            fresh.update(_wm_stamp())
            p.write_text(json.dumps(fresh, ensure_ascii=False), encoding="utf-8")
            data = fresh
        except Exception as e:
            if data is None:
                console.log(f"[yellow]WMN не загрузился и кэша нет: {e}[/]")
                return [], {"count": 0, "stale": True, "error": str(e),
                            **_wm_stamp()}
            data["_stale"] = True
            data["_error"] = str(e)

    out: list[WMNChecker] = []
    for site in data.get("sites", []):
        if site.get("cat") not in cfg.categories:
            continue
        out.append(WMNChecker(
            name=site["name"], uri_check=site["uri_check"],
            e_string=site.get("e_string", ""), m_string=site.get("m_string", ""),
            e_code=site.get("e_code", 200), m_code=site.get("m_code", 404),
        ))
        if cfg.limit and len(out) >= cfg.limit:
            break

    meta = {
        "count": len(out),
        "fetched_at": data.get("_fetched_at", fetched_at),
        "age_days": (time.time() - data.get("_fetched_at", fetched_at)) / 86400,
        "stale": bool(data.get("_stale")),
        "error": data.get("_error"),
        **_wm_stamp(),
    }
    console.log(f"[green]WMN загружено: {len(out)} чекеров "
                f"(age {meta['age_days']:.1f}d)[/]")
    return out, meta


class GitHubUser:
    name = "github"
    kind = "username"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://api.github.com/users/x"

    def _evaluate(self, body: str, code: int, url: str):
        if code != 200:
            return False, None, {}
        if not looks_like_json(body):
            return False, None, {"captcha": True}
        try:
            d = json.loads(body)
        except Exception:
            return False, None, {}
        meta = {
            "name": d.get("name"),
            "bio": d.get("bio"),
            "public_repos": d.get("public_repos"),
            "location": d.get("location"),
            "created_at": d.get("created_at"),
            "avatar_hash": avatar_hash(d.get("avatar_url", "")),
            "emails": [d["email"]] if d.get("email") else [],
        }
        ev = json.dumps({k: v for k, v in meta.items() if v}, ensure_ascii=False)
        return True, ev, meta

    async def check(self, session, target: str) -> Finding:
        url = f"https://api.github.com/users/{quote(target)}"
        async with session.get(url) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = r.headers.get("Retry-After")
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class TelegramUser:
    name = "telegram"
    kind = "username"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://t.me/x"

    def _evaluate(self, body, code, url):
        found = code == 200 and "tgme_page_title" in body
        title = None
        av = None
        if found:
            m = re.search(r'<meta property="og:title" content="([^"]+)"', body)
            title = m.group(1) if m else None
            m2 = re.search(r'<meta property="og:image" content="([^"]+)"', body)
            if m2:
                av = avatar_hash(m2.group(1))
        return found, title, {"name": title, "avatar_hash": av}

    async def check(self, session, target):
        url = f"https://t.me/{quote(target)}"
        async with session.get(url) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class UsernameHTML:
    kind = "username"
    mode = "passive"
    needs_browser = True
    proxy_required = False
    no_network = False

    def __init__(self, name, url_tpl, negative_markers=()):
        self.name = name
        self.url_tpl = url_tpl
        self.negative_markers = negative_markers
        self.url_hint = url_tpl.format(u="x")

    def _evaluate(self, body, code, url):
        found = code == 200 and not any(
            m.lower() in body.lower() for m in self.negative_markers
        )
        blocked = code in (403, 429, 503) or is_blocked_html(body[:2000])
        name = None
        m = re.search(r'<meta property="og:title" content="([^"]+)"', body)
        if m:
            name = m.group(1)
        av = None
        m2 = re.search(r'<meta property="og:image" content="([^"]+)"', body)
        if m2:
            av = avatar_hash(m2.group(1))
        meta = {"blocked": blocked, "name": name, "avatar_hash": av}
        ev = body[:280].replace("\n", " ") if found else None
        return found, ev, meta

    async def check(self, session, target):
        url = self.url_tpl.format(u=quote(target))
        async with session.get(url, allow_redirects=False) as r:
            body = await r.text(errors="ignore") if r.status == 200 else ""
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = r.headers.get("Retry-After")
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class HIBP:
    name = "haveibeenpwned"
    kind = "email"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://haveibeenpwned.com/"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    def _evaluate(self, body, code, url):
        meta = {}
        if code == 404:
            return False, "чисто", meta
        if code == 200:
            if not looks_like_json(body):
                meta["captcha"] = True
                return False, None, meta
            try:
                data = json.loads(body)
                names = [b["Name"] for b in data]
                meta["breaches"] = names
                return True, ", ".join(names[:10]), meta
            except Exception:
                return True, body[:200], meta
        if code == 401:
            meta["dead"] = True
            meta["verify_hint"] = "нужен API-ключ"
        return False, None, meta

    async def check(self, session, target):
        url = (f"https://haveibeenpwned.com/api/v3/breachedaccount/"
               f"{quote(target)}?truncateResponse=false")
        h = {"hibp-api-key": self.api_key} if self.api_key else {}
        async with session.get(url, headers=h) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = r.headers.get("Retry-After")
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class EmailRep:
    name = "emailrep.io"
    kind = "email"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://emailrep.io/"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    def _evaluate(self, body, code, url):
        meta = {}
        if code == 401:
            meta["dead"] = True
            meta["verify_hint"] = "требуется API-ключ (с 2023)"
            return False, None, meta
        if not looks_like_json(body):
            meta["captcha"] = True
            return False, None, meta
        try:
            d = json.loads(body)
        except Exception:
            return False, None, meta
        profiles = d.get("details", {}).get("profiles", []) or []
        found = bool(profiles) or d.get("suspicious", False) \
            or d.get("reputation") not in (None, "none")
        meta.update({
            "reputation": d.get("reputation"),
            "suspicious": d.get("suspicious"),
            "profiles": profiles,
        })
        ev = f"rep={d.get('reputation')} susp={d.get('suspicious')} profiles={profiles[:5]}"
        return found, ev, meta

    async def check(self, session, target):
        url = f"https://emailrep.io/{quote(target)}"
        h = {"User-Agent": "osint-bot"}
        if self.api_key:
            h["Key"] = self.api_key
        async with session.get(url, headers=h) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = r.headers.get("Retry-After")
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found,
                           url=url, status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class EmailRegistered:
    kind = "email"
    mode = "active"
    needs_browser = False
    proxy_required = True
    no_network = False

    def __init__(self, name, method, url, data_tpl=None,
                 found_marker="", not_found_marker="", verify_hint=""):
        self.name = name
        self.method = method
        self.url = url
        self.data_tpl = data_tpl or {}
        self.found_marker = found_marker
        self.not_found_marker = not_found_marker
        self.verify_hint = verify_hint
        self.url_hint = url

    def _evaluate(self, body, code, url):
        meta = {}
        if code in (401, 403, 429):
            meta["dead"] = True
            meta["verify_hint"] = self.verify_hint or "endpoint rot — re-verify"
            return False, None, meta
        if is_blocked_html(body[:3000]):
            meta["captcha"] = True
            return False, None, meta
        if self.not_found_marker and self.not_found_marker in body:
            return False, None, meta
        if self.found_marker and self.found_marker in body:
            return True, body[:160].replace("\n", " "), meta
        found = code in (200, 302)
        return found, (body[:160].replace("\n", " ") if found else None), meta

    async def check(self, session, target):
        data = {k: v.format(email=target) for k, v in self.data_tpl.items()}
        try:
            async with session.request(self.method, self.url, data=data,
                                       allow_redirects=False) as r:
                body = await r.text(errors="ignore")
                found, ev, meta = self._evaluate(body, r.status, self.url)
                meta["retry_after"] = r.headers.get("Retry-After")
                meta.update(_wm_stamp())
                return Finding(source=self.name, target=target, found=found,
                               url=self.url, status=r.status, evidence=ev, meta=meta)
        except Exception as e:
            return Finding(source=self.name, target=target, found=False,
                           url=self.url, error=str(e), meta=_wm_stamp())

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class PhoneIntel:
    name = "phone-intel"
    kind = "phone"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = True

    async def check(self, session, target):
        try:
            pn = phonenumbers.parse(target, None)
        except NumberParseException as e:
            return Finding(source=self.name, target=target, found=False,
                           error=f"parse: {e}", meta=_wm_stamp())
        valid = phonenumbers.is_valid_number(pn)
        region = phonenumbers.region_code_for_number(pn)
        carrier_name = carrier.name_for_number(pn, "en") or None
        location = geocoder.description_for_number(pn, "ru") or None
        ntype = phonenumbers.number_type(pn)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
            phonenumbers.PhoneNumberType.VOIP: "voip",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
        }
        e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
        meta = {
            "e164": e164,
            "international": phonenumbers.format_number(
                pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "region": region, "carrier": carrier_name, "location": location,
            "type": type_map.get(ntype, "unknown"),
            "phones": [e164] if valid else [],
            **_wm_stamp(),
        }
        return Finding(source=self.name, target=target, found=valid,
                       evidence=f"{meta['international']} · {region or '?'} · "
                                f"{carrier_name or '?'} · {meta['type']}",
                       meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        return Finding(source=self.name, target=target, found=False,
                       meta=_wm_stamp())


class TelegramPhone:
    name = "telegram-phone"
    kind = "phone"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://t.me/"

    def _evaluate(self, body, code, url):
        found = code == 200 and "tgme_page_title" in body
        title = None
        av = None
        if found:
            m = re.search(r'<meta property="og:title" content="([^"]+)"', body)
            title = m.group(1) if m else None
            m2 = re.search(r'<meta property="og:image" content="([^"]+)"', body)
            if m2:
                av = avatar_hash(m2.group(1))
        meta = {"blocked": code in (403, 429), "name": title, "avatar_hash": av}
        return found, title, meta

    async def check(self, session, target):
        digits = re.sub(r"\D", "", target)
        url = f"https://t.me/+{digits}"
        async with session.get(url, allow_redirects=True) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["phones"] = [f"+{digits}"] if found else []
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class WhatsAppPhone:
    name = "whatsapp-phone"
    kind = "phone"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://wa.me/"

    def _evaluate(self, body, code, loc):
        invalid = "invalid" in (loc + body).lower()
        found = code in (200, 301, 302) and not invalid
        return found, (loc or None)[:120], {}

    async def check(self, session, target):
        digits = re.sub(r"\D", "", target)
        url = f"https://wa.me/{digits}"
        async with session.get(url, allow_redirects=False) as r:
            loc = r.headers.get("Location", "")
            body = await r.text(errors="ignore") if r.status == 200 else ""
            found, ev, meta = self._evaluate(body, r.status, loc)
            meta["phones"] = [f"+{digits}"] if found else []
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, "")
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class CourtRUS:
    name = "sudact.ru"
    kind = "fio"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://sudact.ru/"

    def _evaluate(self, body, code, url):
        hits = len(re.findall(r"regular-doc-list__item", body))
        return hits > 0, f"{hits} совпадений", {"count": hits}

    async def check(self, session, target):
        url = f"https://sudact.ru/regular/doc/?regular-txt={quote(target)}"
        async with session.get(url) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = r.headers.get("Retry-After")
            meta["name"] = target
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class CourtRF:
    name = "sudrf.ru"
    kind = "fio"
    mode = "passive"
    needs_browser = True
    proxy_required = False
    no_network = False
    url_hint = "https://sudrf.ru/"

    def _evaluate(self, body, code, url):
        captcha = is_blocked_html(body[:3000])
        hits = len(re.findall(r'href="[^"]*case_id=', body))
        meta = {"captcha": captcha, "blocked": captcha, "count": hits}
        ev = f"{hits} дел" + (" · captcha" if captcha else "")
        return (hits > 0 and not captcha), ev, meta

    async def check(self, session, target):
        url = f"https://sudrf.ru/index.php?id=300&fio={quote(target)}"
        async with session.get(url) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = r.headers.get("Retry-After")
            meta["name"] = target
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class CourtBankrupt:
    name = "bankrot.fedresurs.ru"
    kind = "fio"
    mode = "passive"
    needs_browser = True
    proxy_required = False
    no_network = False
    url_hint = "https://bankrot.fedresurs.ru/"

    def _evaluate(self, body, code, url):
        if not looks_like_json(body):
            return False, None, {"captcha": True}
        try:
            d = json.loads(body)
            n = len(d.get("persons", []) or [])
        except Exception:
            n = 0
        return n > 0, f"{n} записей", {"count": n}

    async def check(self, session, target):
        url = (f"https://bankrot.fedresurs.ru/backend/persons/search"
               f"?searchString={quote(target)}")
        async with session.get(url) as r:
            ra = r.headers.get("Retry-After")
            if r.status != 200:
                return Finding(source=self.name, target=target, found=False,
                               url=url, status=r.status,
                               meta={"retry_after": ra, **_wm_stamp()})
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta["retry_after"] = ra
            meta["name"] = target
            meta.update(_wm_stamp())
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class DomainRecon:
    name = "domain-whois"
    kind = "domain"
    mode = "passive"
    needs_browser = False
    proxy_required = False
    no_network = False
    url_hint = "https://rdap.org/"

    def _evaluate(self, body, code, url):
        if code != 200:
            return False, None, {}
        if not looks_like_json(body):
            return False, None, {"captcha": True}
        try:
            d = json.loads(body)
        except Exception:
            return False, None, {}
        events = {e.get("eventAction"): e.get("eventDate")
                  for e in d.get("events", [])}
        return True, f"registered={events.get('registration')}", \
            {"events": events, "status": d.get("status")}

    async def check(self, session, target):
        url = f"https://rdap.org/domain/{quote(target)}"
        async with session.get(url) as r:
            body = await r.text(errors="ignore")
            found, ev, meta = self._evaluate(body, r.status, url)
            meta.update(_wm_stamp())
            if r.status != 200 and not meta:
                meta["retry_after"] = r.headers.get("Retry-After")
                return Finding(source=self.name, target=target, found=False,
                               url=url, status=r.status,
                               error=f"http {r.status}", meta=meta)
            return Finding(source=self.name, target=target, found=found, url=url,
                           status=r.status, evidence=ev, meta=meta)

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


class DorkChecker:
    kind = "username"
    mode = "active"
    needs_browser = True
    proxy_required = True
    no_network = False
    name = "ddg-dorks"
    url_hint = "https://html.duckduckgo.com/html/"

    TEMPLATES = [
        '"{q}" site:pastebin.com',
        '"{q}" site:github.com',
        '"{q}" site:linkedin.com',
        '"{q}" -site:github.com -site:linkedin.com',
        '"{q}" email',
        '"{q}" "@gmail.com" OR "@yandex.ru" OR "@mail.ru"',
    ]

    def _evaluate(self, body, code, url):
        hits = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', body, re.S)
        clean = [re.sub(r"<[^>]+>", "", h).strip()[:200] for h in hits[:5]]
        return bool(clean), (f"{len(clean)} сниппетов" if clean else None), \
            {"snippets": clean}

    async def check(self, session, target):
        results = []
        for tpl in self.TEMPLATES:
            q = tpl.format(q=target)
            url = f"https://html.duckduckgo.com/html/?q={quote(q)}"
            try:
                async with session.get(url) as r:
                    body = await r.text(errors="ignore")
                    found, ev, meta = self._evaluate(body, r.status, url)
                    if found:
                        results.append({"query": q, "url": url,
                                        "snippets": meta["snippets"]})
            except Exception:
                continue
        return Finding(
            source=self.name, target=target, found=bool(results),
            url="https://duckduckgo.com/?q=" + quote(target), status=200,
            evidence=f"{len(results)} dorks дали результаты",
            meta={"dorks": results, **_wm_stamp()})

    def evaluate_html(self, body, code, url, target) -> Finding:
        found, ev, meta = self._evaluate(body, code, url)
        meta.update(_wm_stamp())
        return Finding(source=self.name, target=target, found=found,
                       url=url, status=code, evidence=ev, meta=meta)


# ============================================================================
# ==============================  ПРЕСЕТЫ  ===================================
# ============================================================================

def default_username_checkers() -> list[Checker]:
    return [
        UsernameHTML("reddit", "https://www.reddit.com/user/{u}",
                     ("page not found", "nobody on reddit")),
        UsernameHTML("habr", "https://habr.com/ru/users/{u}/",
                     ("404", "not found")),
        UsernameHTML("pikabu", "https://pikabu.ru/@{u}", ("404",)),
        UsernameHTML("vk", "https://vk.com/{u}", ("profile not found",)),
        UsernameHTML("ok", "https://ok.ru/{u}", ("not found",)),
        UsernameHTML("instagram", "https://www.instagram.com/{u}/",
                     ("page not found",)),
        UsernameHTML("tiktok", "https://www.tiktok.com/@{u}",
                     ("couldn't find this account",)),
        UsernameHTML("twitch", "https://www.twitch.tv/{u}",
                     ("channel not found",)),
        UsernameHTML("steam", "https://steamcommunity.com/id/{u}",
                     ("the specified profile could not be found",)),
        UsernameHTML("pypi", "https://pypi.org/user/{u}/", ("not found",)),
        UsernameHTML("npm", "https://www.npmjs.com/~{u}", ("could not find",)),
        TelegramUser(),
        GitHubUser(),
    ]


def default_email_checkers(secrets: Secrets,
                           checkers_cfg: dict) -> list[Checker]:
    out: list[Checker] = []
    out.append(HIBP(api_key=secrets.hibp_key))
    out.append(EmailRep(api_key=secrets.emailrep_key))
    return out


def default_phone_checkers() -> list[Checker]:
    return [PhoneIntel(), TelegramPhone(), WhatsAppPhone()]


def default_fio_checkers() -> list[Checker]:
    return [CourtRUS(), CourtRF(), CourtBankrot()]


# ============================================================================
# ================================  ЯДРО  ====================================
# ============================================================================

class OSINTEngine:
    def __init__(
        self,
        concurrency: int = 25,
        timeout: float = 12.0,
        retries: int = 3,
        proxy_pool: ProxyPool | None = None,
        max_retry_after: float = 60.0,
        cache: Cache | None = None,
        mode: str = "passive",
        branded: bool = False,
        jitter: float = 0.0,
        breaker_threshold: int = 5,
        breaker_cooldown: float = 300.0,
    ):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.retries = retries
        self.proxy_pool = proxy_pool
        self.max_retry_after = max_retry_after
        self.cache = cache
        self.mode = mode
        self.branded = branded
        self.jitter = jitter
        # UA фиксирован на сессию — запросы не коррелируют по UA
        self._session_ua = random.choice(UA_POOL)
        self.limiter = HostLimiter(breaker_threshold=breaker_threshold,
                                   breaker_cooldown=breaker_cooldown)
        self.checkers: list[Checker] = []
        self._browser: Any = None
        self._correlation: dict = {}
        self._health: dict = {}
        self._wmn_meta: dict = {}

    def register(self, *checkers: Checker) -> "OSINTEngine":
        self.checkers.extend(checkers)
        return self

    def enable_browser(self) -> bool:
        try:
            from browser_fallback import BrowserPool
            self._browser = BrowserPool(size=2)
            return True
        except Exception:
            console.log("[yellow]playwright недоступен — JS-фолбэк выключен[/]")
            return False

    async def _make_session(self, proxy_url: str | None) -> aiohttp.ClientSession:
        if proxy_url and proxy_url.startswith("socks"):
            connector = ProxyConnector.from_url(proxy_url)
        else:
            connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=300)
        return aiohttp.ClientSession(
            timeout=self.timeout,
            headers=headers(branded=self.branded, ua=self._session_ua),
            connector=connector, trust_env=False,
        )

    def _eligible(self, c: Checker, t: str) -> bool:
        if self.mode == "passive" and c.mode == "active":
            return False
        if c.kind == "username":
            if looks_like_email(t) or looks_like_domain(t) \
                    or looks_like_phone(t) or looks_like_fio(t):
                return False
            return True
        if c.kind == "email" and looks_like_email(t):
            return True
        if c.kind == "domain" and looks_like_domain(t):
            return True
        if c.kind == "phone" and looks_like_phone(t):
            return True
        if c.kind == "fio" and looks_like_fio(t):
            return True
        return False

    async def _run_one(self, checker: Checker, target: str) -> Finding:
        if getattr(checker, "no_network", False):
            f = await checker.check(None, target)
            f.mode = checker.mode
            return f

        if self.cache:
            hit = await self.cache.get(checker.name, target)
            if hit:
                return hit

        if getattr(checker, "proxy_required", False) and not self.proxy_pool:
            return Finding(source=checker.name, target=target, found=False,
                           error="proxy_required, no pool",
                           meta={"skipped": True, **_wm_stamp()},
                           mode=checker.mode)

        async with self.sem:
            last_err = None
            for attempt in range(self.retries + 1):
                proxy_url = await self.proxy_pool.current() if self.proxy_pool else None
                proxy_arg = None
                if proxy_url and not proxy_url.startswith("socks"):
                    proxy_arg = proxy_url

                session = await self._make_session(proxy_url)
                t0 = time.perf_counter()
                try:
                    async with session:
                        hint_url = getattr(checker, "url_hint", None) or \
                            getattr(checker, "url_tpl", "").format(u=target) or \
                            "https://unknown/"

                        # circuit breaker: хост в карантине — не идём
                        if self.limiter.is_tripped(hint_url):
                            return Finding(
                                source=checker.name, target=target,
                                found=False,
                                error="circuit_breaker: host in quarantine",
                                meta={"skipped": True,
                                      "verify_hint": "host kicked N×429/403/503",
                                      **_wm_stamp()},
                                mode=checker.mode)

                        await self.limiter.acquire(hint_url)

                        # anti-pattern jitter: рандомная задержка
                        if self.jitter > 0:
                            await asyncio.sleep(random.uniform(0, self.jitter))

                        if hasattr(checker, "check_with_session"):
                            f = await checker.check_with_session(session, target, proxy_arg)
                        else:
                            f = await checker.check(session, target)

                        f.elapsed_ms = int((time.perf_counter() - t0) * 1000)
                        f.mode = checker.mode

                        # circuit breaker: фиксируем исход хоста
                        if f.status in (429, 403, 503):
                            self.limiter.record_failure(hint_url)
                        elif f.status and f.status < 400:
                            self.limiter.record_success(hint_url)

                        f.meta.setdefault("_generator", "hydra")
                        f.meta.setdefault("_author", HYDRA_HANDLE)
                        f.meta.setdefault("_channel", HYDRA_CHANNEL)
                        f.meta.setdefault("_signature", HYDRA_SIGNATURE)

                        if f.status == 429:
                            ra = parse_retry_after(f.meta.get("retry_after"))
                            if ra is not None:
                                wait = min(ra, self.max_retry_after)
                                console.log(
                                    f"[yellow]429 → sleep {wait:.1f}s[/] "
                                    f"({checker.name}/{target})")
                                await asyncio.sleep(wait)
                            if self.proxy_pool:
                                await self.proxy_pool.force_rotate()

                        if (f.meta.get("blocked") or f.status in (403, 503)) \
                                and self._browser is not None \
                                and getattr(checker, "needs_browser", False):
                            try:
                                code, body = await self._browser.fetch(hint_url)
                                f = checker.evaluate_html(body, code, hint_url, target)
                                f.mode = checker.mode
                                f.meta["via"] = "browser"
                            except Exception as e:
                                f.meta["browser_error"] = str(e)

                        if self.cache:
                            await self.cache.put(f)
                        return f

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last_err = e
                    if self.proxy_pool:
                        await self.proxy_pool.force_rotate()
                    await asyncio.sleep(0.4 * (attempt + 1) + random.random() * 0.3)

            return Finding(source=checker.name, target=target, found=False,
                           error=str(last_err) if last_err else "unknown",
                           mode=checker.mode, meta=_wm_stamp())

    async def scan(self, targets: Iterable[str]) -> list[Finding]:
        jobs = [(c, t) for t in targets for c in self.checkers if self._eligible(c, t)]
        results: list[Finding] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as prog:
            task = prog.add_task(
                f"scanning · HYDRA v{HYDRA_VERSION} · {HYDRA_HANDLE}",
                total=len(jobs))
            for coro in asyncio.as_completed([self._run_one(c, t) for c, t in jobs]):
                f = await coro
                results.append(f)
                color = "green" if f.found else ("yellow" if f.error else "dim")
                tag = "[cyan]cache[/]" if f.from_cache else ""
                prog.log(f"[{color}]{f.source:18} {f.target:22} "
                         f"status={f.status}[/] {tag}")
                prog.advance(task)

        corr = correlate(results)
        for f in results:
            if not f.found:
                continue
            c = 0
            for e in (f.meta.get("emails") or []):
                if len(corr["by_email"].get(e.lower(), [])) > 1:
                    c += 1
            for p in (f.meta.get("phones") or []):
                if len(corr["by_phone"].get(p, [])) > 1:
                    c += 1
            if f.meta.get("avatar_hash"):
                if len(corr["by_avatar"].get(f.meta["avatar_hash"], [])) > 1:
                    c += 1
            f.confidence = score_finding(f, corroboration=c)

        self._correlation = corr
        self._health = health_report(results)
        return results


# ============================================================================
# ==============================  ВЫВОД  =====================================
# ============================================================================

def render_console(findings: list[Finding], health: dict | None = None) -> None:
    console.rule(f"[bold magenta]HYDRA v{HYDRA_VERSION} · {HYDRA_HANDLE} · "
                 f"{HYDRA_CHANNEL}[/]")
    hits = [f for f in findings if f.found]
    blocked = [f for f in findings if f.meta.get("blocked") or f.meta.get("captcha")]
    errors = [f for f in findings if f.error]
    skipped = [f for f in findings if f.meta.get("skipped")]

    console.rule(f"[bold green]HITS ({len(hits)})")
    if hits:
        t = Table(show_header=True, header_style="bold magenta", expand=True)
        t.add_column("source", style="cyan", no_wrap=True)
        t.add_column("target", style="white")
        t.add_column("conf", justify="center")
        t.add_column("status", justify="right", style="green")
        t.add_column("evidence")
        t.add_column("url", style="blue", overflow="fold")
        for f in hits:
            c = {"high": "green", "medium": "yellow", "low": "red"}.get(
                f.confidence, "dim")
            t.add_row(f.source, f.target, f"[{c}]{f.confidence}[/]",
                      str(f.status or ""), (f.evidence or "")[:80], f.url or "")
        console.print(t)

    if blocked:
        console.rule(f"[bold yellow]BLOCKED / CAPTCHA ({len(blocked)})")
        for f in blocked:
            console.print(f"  [yellow]{f.source:18}[/] {f.target:22} "
                          f"[red]{f.status}[/]")

    if errors:
        console.rule(f"[bold red]ERRORS ({len(errors)})")
        for f in errors:
            console.print(f"  [red]{f.source:18}[/] {f.target:22} {f.error}")

    if skipped:
        console.rule(f"[bold dim]SKIPPED ({len(skipped)})")
        for f in skipped:
            console.print(f"  [dim]{f.source:18}[/] {f.target:22} "
                          f"{f.error or 'skipped'}")

    dead = [f for f in findings if f.meta.get("dead")]
    if dead:
        console.rule(f"[bold red]DEAD / ROT ({len(dead)}) — re-verify endpoints")
        for f in dead:
            console.print(f"  [red]{f.source:18}[/] "
                          f"{f.meta.get('verify_hint', 'endpoint rot')}")

    if health:
        rot = [s for s, h in health.items()
               if h["runs"] > 0 and h["hits"] == 0
               and (h["dead"] + h["captcha"]) >= h["runs"]]
        if rot:
            console.rule(f"[bold red]HEALTH — ROT CANDIDATES ({len(rot)})")
            for s in rot:
                console.print(f"  [red]{s:18}[/] {health[s]}")

    console.print(f"[dim]generated by HYDRA v{HYDRA_VERSION} · "
                  f"{HYDRA_HANDLE} · {HYDRA_CHANNEL}[/]")


def render_html(findings, correlation, health, wmn_meta, path):
    hits = [f for f in findings if f.found]
    blocked = [f for f in findings if f.meta.get("blocked") or f.meta.get("captcha")]
    errors = [f for f in findings if f.error]

    def row(f: Finding) -> str:
        conf = html_escape(f.confidence)
        return (
            f'<tr class="{conf}">'
            f"<td>{html_escape(f.source)}</td>"
            f"<td>{html_escape(f.target)}</td>"
            f'<td><span class="conf {conf}">{conf}</span></td>'
            f"<td>{html_escape(str(f.status or ''))}</td>"
            f'<td class="ev">{html_escape((f.evidence or "")[:200])}</td>'
            f'<td><a href="{html_escape(f.url or "#", quote=True)}" '
            f'target="_blank" rel="noopener noreferrer">'
            f'{html_escape(f.url or "")}</a></td></tr>'
        )

    corr_html = ""
    for key, label in [("by_email", "email"), ("by_phone", "phone"),
                       ("by_avatar", "avatar"), ("by_name", "name")]:
        if correlation.get(key):
            corr_html += f"<h3>{label}</h3><ul>"
            for k, v in correlation[key].items():
                corr_html += (f"<li><code>{html_escape(k)}</code> → "
                              f"{html_escape(', '.join(v))}</li>")
            corr_html += "</ul>"

    health_html = ""
    if health:
        health_html = ("<table><thead><tr><th>source</th><th>runs</th>"
                       "<th>hits</th><th>dead</th><th>captcha</th>"
                       "<th>errors</th><th>skipped</th></tr></thead><tbody>")
        for s, h in sorted(health.items()):
            health_html += (
                f"<tr><td>{html_escape(s)}</td><td>{h['runs']}</td>"
                f"<td>{h['hits']}</td><td>{h['dead']}</td>"
                f"<td>{h['captcha']}</td><td>{h['errors']}</td>"
                f"<td>{h['skipped']}</td></tr>")
        health_html += "</tbody></table>"

    wmn_html = ""
    if wmn_meta:
        wmn_html = (f"<p>WMN: {wmn_meta.get('count', 0)} чекеров · "
                    f"age {wmn_meta.get('age_days', 0):.1f}d · "
                    f"stale={wmn_meta.get('stale', False)}</p>")

    wm_comment = (
        f"<!-- Generated by HYDRA v{HYDRA_VERSION} | "
        f"{HYDRA_HANDLE} | {HYDRA_REPO} | {HYDRA_CHANNEL} | "
        f"signature={HYDRA_SIGNATURE} | fingerprint={HYDRA_FINGERPRINT} -->"
    )

    html = f"""{wm_comment}
<!doctype html><html><head><meta charset="utf-8">
<meta name="generator" content="HYDRA v{HYDRA_VERSION} by {HYDRA_HANDLE}">
<meta name="author" content="{HYDRA_AUTHOR} {HYDRA_HANDLE}">
<meta name="x-hydra-signature" content="{HYDRA_SIGNATURE}">
<title>HYDRA report · {HYDRA_HANDLE}</title>
<style>
body{{font:14px/1.5 -apple-system,Segoe UI,sans-serif;margin:2rem;color:#222}}
h1{{margin:0 0 1rem}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}}
th{{background:#f4f4f4}}
.ev{{font-family:ui-monospace,monospace;font-size:12px;color:#555;
    max-width:400px;overflow:hidden;text-overflow:ellipsis}}
.conf{{padding:.1rem .5rem;border-radius:3px;color:#fff;font-size:11px}}
.conf.high{{background:#2e7d32}} .conf.medium{{background:#ef6c00}}
.conf.low{{background:#c62828}}
tr.high{{background:#f1f8e9}} tr.medium{{background:#fff8e1}}
code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}}
.wm{{margin-top:3rem;padding-top:1rem;border-top:1px dashed #ccc;
     color:#888;font-size:12px;text-align:center}}
.wm a{{color:#888}}
</style></head><body>
<h1>HYDRA report</h1>
<p class="wm">generated by HYDRA v{HYDRA_VERSION} ·
   author <a href="{HYDRA_REPO}">{HYDRA_HANDLE}</a> ·
   channel <a href="{HYDRA_CHANNEL}">{HYDRA_CHANNEL}</a></p>
<p>targets: {len(set(f.target for f in findings))} · hits: {len(hits)} ·
blocked: {len(blocked)} · errors: {len(errors)}</p>
{wmn_html}
<h2>Hits</h2>
<table><thead><tr><th>source</th><th>target</th><th>conf</th><th>status</th>
<th>evidence</th><th>url</th></tr></thead>
<tbody>{''.join(row(f) for f in hits)}</tbody></table>
<h2>Correlation</h2>{corr_html or '<p>нет пересечений</p>'}
<h2>Health</h2>{health_html or '<p>нет данных</p>'}
<h2>Blocked ({len(blocked)})</h2><ul>{''.join(
    f'<li>{html_escape(f.source)} · {html_escape(f.target)} · '
    f'{html_escape(str(f.status))}</li>' for f in blocked)}</ul>
<h2>Errors ({len(errors)})</h2><ul>{''.join(
    f'<li>{html_escape(f.source)} · {html_escape(f.target)} · '
    f'{html_escape(f.error or "")}</li>' for f in errors)}</ul>
<div class="wm">
  HYDRA v{HYDRA_VERSION} · © 2026 {HYDRA_AUTHOR} ({HYDRA_HANDLE}) · MIT<br>
  <a href="{HYDRA_REPO}">{HYDRA_REPO}</a> ·
  <a href="{HYDRA_CHANNEL}">{HYDRA_CHANNEL}</a><br>
  <code>{HYDRA_SIGNATURE}</code> · <code>{HYDRA_FINGERPRINT}</code>
</div>
<!-- {HYDRA_COPYRIGHT} -->
</body></html>"""
    Path(path).write_text(html, encoding="utf-8")


def export_csv(findings, path):
    with open(path, "w", newline="", encoding="utf-8") as fp:
        fp.write(f"# {_wm_line()}\n")
        fp.write(f"# {HYDRA_COPYRIGHT}\n")
        fp.write(f"# signature={HYDRA_SIGNATURE} fingerprint={HYDRA_FINGERPRINT}\n")
        w = csv.writer(fp)
        w.writerow(["source", "target", "found", "confidence", "status",
                    "url", "evidence", "error", "mode"])
        for f in findings:
            w.writerow([f.source, f.target, f.found, f.confidence, f.status,
                        f.url, f.evidence, f.error, f.mode])


def export_markdown(findings, correlation, health, path):
    lines = [
        f"<!-- {_wm_line()} -->",
        f"<!-- {HYDRA_COPYRIGHT} -->",
        f"<!-- signature={HYDRA_SIGNATURE} fingerprint={HYDRA_FINGERPRINT} -->",
        "",
        "# HYDRA report",
        f"*by [{HYDRA_AUTHOR}]({HYDRA_REPO}) · [channel]({HYDRA_CHANNEL})*",
        "",
    ]
    hits = [f for f in findings if f.found]
    lines.append(f"**hits:** {len(hits)} · "
                 f"**blocked:** {sum(1 for f in findings if f.meta.get('blocked'))} · "
                 f"**errors:** {sum(1 for f in findings if f.error)}")
    lines.append("")
    lines.append("| source | target | conf | status | evidence | url |")
    lines.append("|---|---|---|---|---|---|")
    for f in hits:
        ev = (f.evidence or "").replace("|", "\\|")[:120]
        lines.append(f"| {f.source} | {f.target} | {f.confidence} | "
                     f"{f.status or ''} | {ev} | {f.url or ''} |")
    if any(correlation.values()):
        lines.append("\n## Correlation\n")
        for k, v in correlation.items():
            for idf, sources in v.items():
                lines.append(f"- **{k}** `{idf}` → {', '.join(sources)}")
    if health:
        lines.append("\n## Health\n")
        lines.append("| source | runs | hits | dead | captcha | errors | skipped |")
        lines.append("|---|---|---|---|---|---|---|")
        for s, h in sorted(health.items()):
            lines.append(f"| {s} | {h['runs']} | {h['hits']} | {h['dead']} | "
                         f"{h['captcha']} | {h['errors']} | {h['skipped']} |")
    lines.append("")
    lines.append("---")
    lines.append(f"*HYDRA v{HYDRA_VERSION} · © 2026 {HYDRA_AUTHOR} "
                 f"({HYDRA_HANDLE}) · [repo]({HYDRA_REPO}) · "
                 f"[channel]({HYDRA_CHANNEL})*")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


# ============================================================================
# ===============================  SMOKE  ====================================
# ============================================================================

SAFE_TARGETS = {
    "username": "torvalds",
    "email": "test@example.com",
    "domain": "example.com",
    "phone": "+14155552671",
    "fio": "Иванов Иван",
}


async def run_smoke(engine: OSINTEngine) -> int:
    results = []
    for c in engine.checkers:
        target = SAFE_TARGETS.get(c.kind)
        if not target:
            continue
        if getattr(c, "no_network", False):
            results.append((c.name, c.kind, c.mode, "skip-network", 0))
            continue
        t0 = time.monotonic()
        try:
            f = await engine._run_one(c, target)
        except Exception as e:
            f = Finding(source=c.name, target=target, found=False,
                        error=str(e), meta={"dead": True, **_wm_stamp()})
        dt = int((time.monotonic() - t0) * 1000)

        if f.meta.get("dead"):
            state = "DEAD"
        elif f.meta.get("captcha") or f.meta.get("blocked"):
            state = "BLOCKED"
        elif f.meta.get("skipped"):
            state = "SKIP"
        elif f.error:
            state = "ERROR"
        elif f.status:
            state = "OK"
        else:
            state = "?"
        results.append((c.name, c.kind, c.mode, state, dt))

    t = Table(title=f"HYDRA smoke report · v{HYDRA_VERSION} · {HYDRA_HANDLE}")
    t.add_column("checker", style="cyan")
    t.add_column("kind")
    t.add_column("mode")
    t.add_column("state", style="bold")
    t.add_column("ms", justify="right")
    for row in results:
        color = {"OK": "green", "DEAD": "red", "BLOCKED": "yellow",
                 "ERROR": "red", "SKIP": "dim",
                 "skip-network": "dim"}.get(row[3], "dim")
        t.add_row(row[0], row[1], row[2], f"[{color}]{row[3]}[/]", str(row[4]))
    console.print(t)

    ok = sum(1 for r in results if r[3] == "OK")
    dead = sum(1 for r in results if r[3] == "DEAD")
    blocked = sum(1 for r in results if r[3] == "BLOCKED")
    console.print(f"\n[bold]OK[/]: {ok} · [red]DEAD[/]: {dead} · "
                  f"[yellow]BLOCKED[/]: {blocked} · total: {len(results)}")
    return 0 if dead == 0 else 1


# ============================================================================
# ================================  CLI  =====================================
# ============================================================================

async def cmd_scan(cfg: Config, secrets: Secrets, args) -> int:
    proxies = args.proxy or cfg.proxy.list
    pool = ProxyPool(proxies, rotate_every=cfg.proxy.rotate_every) if proxies else None
    cache_enabled = not getattr(args, "no_cache", False)
    cache = Cache(path=cfg.engine.cache_path, ttl=cfg.engine.cache_ttl,
                  enabled=cache_enabled)
    await cache._init()

    mode = args.mode or cfg.engine.mode
    if mode == "active" and not (args.allow_active or cfg.allow_active):
        console.print("[red]--mode active требует --allow-active (или allow_active: true в конфиге)[/]")
        return 2

    engine = OSINTEngine(
        concurrency=args.concurrency or cfg.engine.concurrency,
        timeout=cfg.engine.timeout,
        retries=cfg.engine.retries,
        proxy_pool=pool, cache=cache, mode=mode,
        max_retry_after=cfg.engine.max_retry_after,
        branded=getattr(args, "branded", False),
        jitter=getattr(args, "jitter", 0.0),
        breaker_threshold=getattr(cfg.engine, "breaker_threshold", 5),
        breaker_cooldown=getattr(cfg.engine, "breaker_cooldown", 300.0),
    )

    engine.register(*default_username_checkers())
    engine.register(*default_email_checkers(secrets, cfg.checkers))
    engine.register(*default_phone_checkers())
    engine.register(*default_fio_checkers())

    if cfg.wmn.enabled and not args.no_wmn:
        wmn_checkers, wmn_meta = await load_wmn(cfg.wmn)
        engine.register(*wmn_checkers)
        engine._wmn_meta = wmn_meta

    if args.dorks:
        if not pool or pool.empty:
            console.log("[red]--dorks требует --proxy[/]")
        else:
            engine.register(DorkChecker())

    if args.recovery_forms:
        if mode != "active":
            console.log("[red]--recovery-forms требует --mode active[/]")
        elif not pool or pool.empty:
            console.log("[yellow]--recovery-forms без прокси — скипнется[/]")
        engine.register(EmailRegistered(
            "instagram-recovery", "POST",
            "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
            data_tpl={"email": "{email}"},
            verify_hint="instagram recovery API менялся 2024 Q3"))

    if args.browser:
        engine.enable_browser()

    scan_targets = list(args.targets) + list(args.fio)
    findings = await engine.scan(scan_targets)

    render_console(findings, engine._health)
    out = args.out
    render_html(findings, engine._correlation, engine._health,
                engine._wmn_meta, out.replace(".json", ".html"))
    export_csv(findings, out.replace(".json", ".csv"))
    export_markdown(findings, engine._correlation, engine._health,
                    out.replace(".json", ".md"))
    export_graph(findings, out.replace(".json", ".graph.json"),
                 out.replace(".json", ".mmd"))

    payload = {
        **_wm_stamp(),
        "targets": scan_targets,
        "findings": [asdict(f) for f in findings],
        "correlation": engine._correlation,
        "health": engine._health,
        "wmn": engine._wmn_meta,
    }
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)

    console.print(f"\n[dim]reports:[/] {out}, "
                  f"{out.replace('.json','.html')}, "
                  f"{out.replace('.json','.csv')}, "
                  f"{out.replace('.json','.md')}, "
                  f"{out.replace('.json','.graph.json')}, "
                  f"{out.replace('.json','.mmd')}")

    if getattr(args, "wipe", False):
        cache.wipe()
        console.print("[dim]cache wiped[/]")
    return 0


async def cmd_smoke(cfg: Config, secrets: Secrets, args) -> int:
    proxies = args.proxy or cfg.proxy.list
    pool = ProxyPool(proxies, rotate_every=cfg.proxy.rotate_every) if proxies else None
    cache = Cache(path=cfg.engine.cache_path + ".smoke", ttl=60)
    engine = OSINTEngine(
        concurrency=8, timeout=8.0, retries=1,
        proxy_pool=pool, cache=cache, mode="active",
        branded=getattr(args, "branded", False),
        jitter=getattr(args, "jitter", 0.0),
    )
    engine.register(*default_username_checkers())
    engine.register(*default_email_checkers(secrets, cfg.checkers))
    engine.register(*default_phone_checkers())
    engine.register(*default_fio_checkers())
    if cfg.wmn.enabled:
        wmn_checkers, _ = await load_wmn(cfg.wmn)
        engine.register(*wmn_checkers)
    if args.dorks and pool and not pool.empty:
        engine.register(DorkChecker())
    return await run_smoke(engine)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hydra",
        description=(f"HYDRA v{HYDRA_VERSION} — multi-source OSINT core · "
                     f"{HYDRA_HANDLE} · {HYDRA_CHANNEL}"),
    )
    ap.add_argument("--config", default="hydra.yaml")
    ap.add_argument("--out", default="hydra_report.json")
    ap.add_argument("--proxy", nargs="*", default=None)
    ap.add_argument("--mode", choices=["passive", "active"], default=None)
    ap.add_argument("--allow-active", action="store_true")
    ap.add_argument("--no-wmn", action="store_true")
    ap.add_argument("--browser", action="store_true")
    ap.add_argument("--dorks", action="store_true")
    ap.add_argument("--recovery-forms", action="store_true")
    ap.add_argument("--concurrency", type=int, default=None)
    ap.add_argument("--branded", action="store_true",
                    help="branded UA + X-Hydra-* заголовки в сети "
                         "(по умолчанию — выкл, OPSEC)")
    ap.add_argument("--no-cache", action="store_true",
                    help="отключить SQLite-кэш (не оставлять следов)")
    ap.add_argument("--wipe", action="store_true",
                    help="удалить кэш-файлы после прогона")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="макс. рандомная задержка перед запросом, сек "
                         "(0 = выкл; 0.3 = ±300ms)")
    ap.add_argument("--smoke", action="store_true",
                    help="self-check: прогнать безопасные цели по всем чекерам")

    sub = ap.add_subparsers(dest="cmd")
    sp = sub.add_parser("scan", help="scan targets")
    sp.add_argument("targets", nargs="*")
    sp.add_argument("--fio", nargs="*", default=[])
    return ap


async def _dispatch(args) -> int:
    cfg = Config.load(args.config)
    secrets = Secrets()

    if args.smoke:
        return await cmd_smoke(cfg, secrets, args)

    if args.cmd == "scan":
        return await cmd_scan(cfg, secrets, args)

    if getattr(args, "targets", None):
        return await cmd_scan(cfg, secrets, args)

    build_parser().print_help()
    return 0


def main() -> int:
    console.print(f"[bold magenta]HYDRA v{HYDRA_VERSION}[/] · "
                  f"[cyan]{HYDRA_HANDLE}[/] · "
                  f"[dim]{HYDRA_CHANNEL}[/]")
    args = build_parser().parse_args()

    if args.cmd is None and not args.smoke:
        raw = [a for a in sys.argv[1:] if not a.startswith("-")]
        raw = [a for a in raw if a not in ("scan",)]
        if raw and not args.smoke:
            args.cmd = "scan"
            args.targets = raw
            args.fio = getattr(args, "fio", []) or []

    try:
        return asyncio.run(_dispatch(args))
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted — closing clean[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
# language: Python 3.11+, file: app.py
# HYDRA web UI — local Flask wrapper
# Copyright (c) 2026 MrInvenix (@MrInvenix) — MIT
# Repo:    https://github.com/MrInvenix/hydra
# Channel: https://t.me/info_by_invenix
# Signature: hydra::v5::MrInvenix::2026
#
# Запуск:  python app.py
# Открыть: http://127.0.0.1:5000
#
# По умолчанию слушает только localhost — снаружи недоступен.
# Хочешь с телефона в той же сети — раскомментируй HOST = "0.0.0.0"
# и добавь пароль (см. ниже).

from __future__ import annotations

import asyncio
import json
import queue
import threading
import time
from pathlib import Path

from flask import (Flask, Response, jsonify, render_template, request,
                   send_file)

# ── импорт ядра HYDRA ────────────────────────────────────────────────
try:
    from hydra import (
        HYDRA_VERSION, HYDRA_HANDLE, HYDRA_CHANNEL,
        OSINTEngine, Cache, ProxyPool,
        default_username_checkers, default_email_checkers,
        default_phone_checkers, default_fio_checkers,
        load_wmn, Config, Secrets,
        render_html, export_csv, export_markdown, export_graph,
    )
except ImportError:
    print("❌ hydra.py не найден. Положи app.py рядом с hydra.py.")
    raise SystemExit(1)


HOST = "127.0.0.1"
PORT = 5000

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

# глобальное состояние прогресса: job_id → очередь событий
_jobs: dict[str, "queue.Queue[dict]"] = {}
_jobs_lock = threading.Lock()


def _emit(job_id: str, event: dict) -> None:
    with _jobs_lock:
        q = _jobs.get(job_id)
    if q is not None:
        q.put(event)


# ── фон: запуск скана в отдельном потоке ─────────────────────────────
def _run_scan(job_id: str, target: str, mode: str,
              use_wmn: bool, concurrency: int) -> None:
    async def runner():
        cfg = Config.load("hydra.yaml")
        secrets = Secrets()

        cache = Cache(path="osint_cache.db", ttl=cfg.engine.cache_ttl,
                      enabled=True)
        await cache._init()

        engine = OSINTEngine(
            concurrency=concurrency,
            timeout=cfg.engine.timeout,
            retries=cfg.engine.retries,
            cache=cache, mode=mode,
            max_retry_after=cfg.engine.max_retry_after,
        )

        engine.register(*default_username_checkers())
        engine.register(*default_email_checkers(secrets, cfg.checkers))
        engine.register(*default_phone_checkers())
        engine.register(*default_fio_checkers())

        if use_wmn and cfg.wmn.enabled:
            wmn, _ = await load_wmn(cfg.wmn)
            engine.register(*wmn)

        total = len([c for c in engine.checkers
                     if engine._eligible(c, target)])
        _emit(job_id, {"type": "start", "total": total})

        done = {"n": 0}
        found_acc: list[dict] = []

        # перехватываем результаты по мере готовности
        async def _one(c, t):
            f = await engine._run_one(c, t)
            done["n"] += 1
            if f.found:
                found_acc.append({
                    "source": f.source, "target": f.target,
                    "confidence": f.confidence, "status": f.status,
                    "url": f.url, "evidence": (f.evidence or "")[:200],
                })
            _emit(job_id, {
                "type": "progress",
                "done": done["n"],
                "total": total,
                "source": f.source,
                "status": f.status,
                "found": f.found,
                "elapsed_ms": f.elapsed_ms,
            })
            return f

        jobs_list = [(c, target) for c in engine.checkers
                     if engine._eligible(c, target)]
        await asyncio.gather(*[_one(c, t) for c, t in jobs_list])

        _emit(job_id, {
            "type": "done",
            "hits": found_acc,
            "total_hits": len(found_acc),
            "total_checks": total,
        })

    try:
        asyncio.run(runner())
    except Exception as e:
        _emit(job_id, {"type": "error", "message": str(e)})
    finally:
        _emit(job_id, {"type": "close"})


# ── маршруты ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template(
        "index.html",
        version=HYDRA_VERSION,
        handle=HYDRA_HANDLE,
        channel=HYDRA_CHANNEL,
    )


@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "empty target"}), 400

    mode = data.get("mode", "passive")
    use_wmn = bool(data.get("use_wmn", True))
    concurrency = int(data.get("concurrency", 25))

    job_id = f"job_{int(time.time()*1000)}"
    with _jobs_lock:
        _jobs[job_id] = queue.Queue()

    t = threading.Thread(
        target=_run_scan,
        args=(job_id, target, mode, use_wmn, concurrency),
        daemon=True,
    )
    t.start()
    return jsonify({"job_id": job_id})


@app.route("/events/<job_id>")
def events(job_id):
    def stream():
        with _jobs_lock:
            q = _jobs.get(job_id)
        if q is None:
            yield "data: {\"type\":\"error\",\"message\":\"no job\"}\n\n"
            return
        while True:
            try:
                ev = q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
            if ev.get("type") == "close":
                with _jobs_lock:
                    _jobs.pop(job_id, None)
                return

    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    print(f"⚡ HYDRA v{HYDRA_VERSION} · web UI")
    print(f"   {HYDRA_HANDLE} · {HYDRA_CHANNEL}")
    print(f"   → http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
# language: Python 3.11+, file: tests/test_cache.py
# HYDRA · tests · by @MrInvenix · t.me/info_by_invenix

import pytest
from hydra import Cache, Finding


@pytest.mark.asyncio
async def test_cache_hit(tmp_path):
    c = Cache(path=str(tmp_path / "c.db"), ttl=60)
    f = Finding(source="s", target="t", found=True, status=200,
                evidence="hello")
    await c.put(f)
    hit = await c.get("s", "t")
    assert hit is not None and hit.found and hit.evidence == "hello"


@pytest.mark.asyncio
async def test_cache_skips_dead(tmp_path):
    c = Cache(path=str(tmp_path / "c.db"), ttl=60)
    dead = Finding(source="s", target="t", found=False, meta={"dead": True})
    await c.put(dead)
    assert await c.get("s", "t") is None


@pytest.mark.asyncio
async def test_cache_skips_error(tmp_path):
    c = Cache(path=str(tmp_path / "c.db"), ttl=60)
    err = Finding(source="s", target="t", found=False, error="boom")
    await c.put(err)
    assert await c.get("s", "t") is None

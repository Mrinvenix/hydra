# language: Python 3.11+, file: tests/test_core.py
# HYDRA · tests · by @MrInvenix · t.me/info_by_invenix

import pytest
from hydra import (
    looks_like_email, looks_like_domain, looks_like_phone, looks_like_fio,
    parse_retry_after, score_finding, correlate, Finding,
)


class TestLooksLike:
    def test_email(self):
        assert looks_like_email("a@b.co")
        assert not looks_like_email("nope")

    def test_domain(self):
        assert looks_like_domain("example.com")
        assert not looks_like_domain("example")

    def test_phone(self):
        assert looks_like_phone("+14155552671")
        assert not looks_like_phone("abc")

    def test_fio(self):
        assert looks_like_fio("Иванов Иван")
        assert not looks_like_fio("ivan ivanov")


class TestRetryAfter:
    def test_seconds(self):
        assert parse_retry_after("30") == 30.0

    def test_none(self):
        assert parse_retry_after(None) is None

    def test_http_date(self):
        v = parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT")
        assert v == 0.0


class TestScoring:
    def test_low(self):
        f = Finding(source="x", target="y", found=True, status=200)
        assert score_finding(f) == "low"

    def test_high(self):
        f = Finding(source="x", target="y", found=True, status=200,
                    meta={"breaches": ["a"]})
        assert score_finding(f, corroboration=2) == "high"


class TestCorrelate:
    def test_shared_email(self):
        a = Finding(source="vk", target="x", found=True,
                    meta={"emails": ["e@x.ru"]})
        b = Finding(source="ok", target="x", found=True,
                    meta={"emails": ["e@x.ru"]})
        c = Finding(source="tg", target="x", found=True,
                    meta={"emails": ["e@x.ru"]})
        corr = correlate([a, b, c])
        assert corr["by_email"]["e@x.ru"] == ["ok", "tg", "vk"]


class TestWatermark:
    def test_finding_origin(self):
        f = Finding(source="x", target="y", found=True)
        assert f._origin.startswith("hydra")

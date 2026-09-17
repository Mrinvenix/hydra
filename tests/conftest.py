# HYDRA · tests · by @MrInvenix · t.me/info_by_invenix
import asyncio
import pytest


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

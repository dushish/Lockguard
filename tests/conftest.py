"""Shared fixtures. The whole suite runs with network access disabled."""

from __future__ import annotations

import socket
import sys
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import lockguard.registry as registry_module
from lockguard.demo import DemoSetup, build_demo
from lockguard.registry import NotFoundError, packument_url

sys.path.insert(0, str(Path(__file__).parent))


def _blocked(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("network access attempted during tests")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly if anything tries to reach the network."""
    monkeypatch.setattr(registry_module, "urlopen_bytes", _blocked)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.delenv("LOCKGUARD_REGISTRY", raising=False)


class FakeHTTP:
    """Replacement for :func:`lockguard.registry.urlopen_bytes` serving canned responses."""

    def __init__(self) -> None:
        self.routes: dict[str, bytes | Exception] = {}
        self.calls: list[str] = []

    def add(self, url: str, body: bytes | Exception) -> None:
        self.routes[url] = body

    def serve_demo(self, setup: DemoSetup) -> None:
        """Serve the demo fixtures' packuments and tarballs."""
        import json

        for name, packument in setup.registry.packuments.items():
            self.add(packument_url(name), json.dumps(packument).encode())
        for url, data in setup.registry.tarballs.items():
            self.add(url, data)

    def __call__(self, url: str, **_kwargs: Any) -> bytes:
        self.calls.append(url)
        body = self.routes.get(url)
        if body is None:
            raise NotFoundError(f"{url}: HTTP 404 (fake)")
        if isinstance(body, Exception):
            raise body
        return body


@pytest.fixture
def fake_http(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeHTTP]:
    """Route the registry HTTP layer to an in-memory table."""
    fake = FakeHTTP()
    monkeypatch.setattr(registry_module, "urlopen_bytes", fake)
    yield fake


@pytest.fixture(scope="session")
def demo_setup() -> DemoSetup:
    """The demo fixtures, built once per session."""
    return build_demo()

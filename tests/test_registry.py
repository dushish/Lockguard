from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import FakeHTTP
from lockguard.registry import (
    NotFoundError,
    RegistryClient,
    RegistryError,
    TransientRegistryError,
    is_valid_package_name,
    packument_url,
    tarball_url,
)


def test_urls_for_scoped_and_plain_packages() -> None:
    assert packument_url("@babel/core") == "https://registry.npmjs.org/@babel%2Fcore"
    assert packument_url("debug") == "https://registry.npmjs.org/debug"
    assert tarball_url("@babel/core", "7.0.0") == (
        "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz"
    )
    assert tarball_url("debug", "4.4.1", "https://r.example/") == (
        "https://r.example/debug/-/debug-4.4.1.tgz"
    )


@pytest.mark.parametrize("name", ["debug", "@scope/pkg", "JSONStream", "a.b_c-d"])
def test_valid_names(name: str) -> None:
    assert is_valid_package_name(name)


@pytest.mark.parametrize("name", ["", "../x", "a/b", "@s/../x", "a b", "@/x"])
def test_invalid_names(name: str) -> None:
    assert not is_valid_package_name(name)


def test_packument_is_fetched_once(fake_http: FakeHTTP, tmp_path: Path) -> None:
    fake_http.add(packument_url("a"), json.dumps({"name": "a", "versions": {}}).encode())
    client = RegistryClient(cache_dir=tmp_path)
    assert client.packument("a")["name"] == "a"
    assert client.packument("a")["name"] == "a"
    assert fake_http.calls == [packument_url("a")]


def test_tarballs_are_cached_on_disk(fake_http: FakeHTTP, tmp_path: Path) -> None:
    url = tarball_url("a", "1.0.0")
    fake_http.add(url, b"tgz")
    assert RegistryClient(cache_dir=tmp_path).tarball(url) == b"tgz"
    assert RegistryClient(cache_dir=tmp_path).tarball(url) == b"tgz"
    assert fake_http.calls == [url]


def test_transient_errors_are_retried_then_raised(fake_http: FakeHTTP) -> None:
    url = tarball_url("a", "1.0.0")
    fake_http.add(url, TransientRegistryError("boom"))
    client = RegistryClient(retries=2, backoff=0)
    with pytest.raises(TransientRegistryError):
        client.tarball(url)
    assert fake_http.calls == [url] * 3


def test_not_found_is_not_retried(fake_http: FakeHTTP) -> None:
    client = RegistryClient(retries=2, backoff=0)
    with pytest.raises(NotFoundError):
        client.packument("missing")
    assert len(fake_http.calls) == 1


def test_invalid_input_is_refused_without_network(fake_http: FakeHTTP) -> None:
    client = RegistryClient()
    with pytest.raises(RegistryError):
        client.packument("../../etc/passwd")
    with pytest.raises(RegistryError):
        client.tarball("file:///etc/passwd")
    assert fake_http.calls == []


def test_invalid_json_packument(fake_http: FakeHTTP) -> None:
    fake_http.add(packument_url("a"), b"<html>")
    with pytest.raises(RegistryError, match="invalid JSON"):
        RegistryClient().packument("a")


def test_registry_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCKGUARD_REGISTRY", "https://npm.internal.example/")
    assert RegistryClient().registry_url == "https://npm.internal.example"

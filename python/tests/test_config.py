import base64
import json
import os
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from gate import config
from gate.config import ConfigError, DirSource, EnvSource, Secret, parse_dotenv, parse_duration, parse_source

REQUIRED = {"DATABASE_URL": "postgres://u:p@h/db", "JWT_ISSUER": "https://auth.example.com", "JWT_SIGNING_KEY": "k"}


class MapSource:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = frozendict(values)

    @property
    def name(self) -> str:
        return "map"

    async def load(self) -> frozendict[str, str]:
        return self.values


@pytest.mark.anyio
async def test_load_defaults_and_precedence() -> None:
    cfg = await config.load(
        [MapSource(REQUIRED), MapSource({"HTTP_ADDR": ":9000", "HTTP_TRUSTED_PROXIES": "10.0.0.0/8,172.16.0.1"})]
    )
    assert cfg.http.port == 9000 and cfg.http.host == "0.0.0.0"
    assert cfg.auth.access_token_ttl == timedelta(minutes=15)
    assert len(cfg.http.trusted_networks) == 2
    assert cfg.database.url.reveal() == "postgres://u:p@h/db"


@pytest.mark.anyio
async def test_load_validation() -> None:
    with pytest.raises(ConfigError, match="DATABASE_URL is required"):
        await config.load([MapSource({})])
    with pytest.raises(ConfigError, match="ACCESS_TOKEN_TTL"):
        await config.load([MapSource(REQUIRED | {"ACCESS_TOKEN_TTL": "2h"})])
    with pytest.raises(ConfigError, match="DB_MAX_OPEN_CONNS: invalid literal"):
        await config.load([MapSource(REQUIRED | {"DB_MAX_OPEN_CONNS": "many"})])


def test_secret_is_redacted() -> None:
    s = Secret("hunter2")
    for out in (str(s), repr(s), f"{s}", f"{s!r}", json.dumps({"s": str(s)})):
        assert "hunter2" not in out
    assert s.reveal() == "hunter2"


@pytest.mark.anyio
async def test_config_print_redacts() -> None:
    cfg = await config.load([MapSource(REQUIRED)])
    out = config.to_json(cfg)
    assert "postgres://u:p@h/db" not in out and "[REDACTED]" in out
    assert json.loads(out)["auth"]["refresh_token_ttl"] == "168h"


def test_durations_match_go() -> None:
    assert parse_duration("1h30m") == timedelta(hours=1, minutes=30)
    assert parse_duration("200ms") == timedelta(milliseconds=200)
    assert parse_duration("0") == timedelta(0)
    assert config.format_duration(timedelta(minutes=15)) == "15m"
    assert config.format_duration(timedelta(milliseconds=200)) == "200ms"
    for bad in ["", "15", "1x", "h"]:
        with pytest.raises(ValueError):
            parse_duration(bad)


@pytest.mark.anyio
async def test_env_source_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RBACTEST_HTTP_ADDR", ":1")
    kv = await EnvSource(prefix="RBACTEST_").load()
    assert dict(kv) == {"HTTP_ADDR": ":1"}


@pytest.mark.anyio
async def test_dir_source_kubernetes_layout(tmp_path: Path) -> None:
    # Kubernetes mounts: key -> ..data/key symlink, plus hidden bookkeeping.
    data = tmp_path / "..data"
    data.mkdir()
    (data / "database-url").write_text("postgres://x\n")
    os.symlink(data / "database-url", tmp_path / "database-url")

    assert dict(await DirSource(str(tmp_path)).load()) == {"DATABASE_URL": "postgres://x"}
    assert dict(await DirSource(str(tmp_path / "missing")).load()) == {}


def test_parse_dotenv() -> None:
    kv = parse_dotenv("# c\nexport A=1\nB=\"two words\"\nc.d='x=y'\n\n")
    assert dict(kv) == {"A": "1", "B": "two words", "C_D": "x=y"}


@pytest.mark.anyio
async def test_consul_source() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path != "/v1/kv/rbac" or r.headers.get("X-Consul-Token") != "tok":
            return httpx.Response(403)
        v = base64.b64encode(b":7000").decode()
        return httpx.Response(200, json=[{"Key": "rbac/", "Value": None}, {"Key": "rbac/http_addr", "Value": v}])

    src = parse_source("consul:http://consul.test:8500/rbac")
    assert isinstance(src, config.ConsulSource)
    src = config.ConsulSource(
        address=src.address, prefix=src.prefix, token="tok", transport=httpx.MockTransport(handler)
    )
    assert dict(await src.load()) == {"HTTP_ADDR": ":7000"}


@pytest.mark.anyio
async def test_http_json_source() -> None:
    body = {"HTTP_ADDR": ":6000", "DB_MAX_OPEN_CONNS": 50, "PUBLIC_REGISTRATION_ENABLED": False}
    src = config.HTTPJSONSource(
        "http://appconfig.test/x", transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    )
    kv = await src.load()
    assert kv["DB_MAX_OPEN_CONNS"] == "50" and kv["PUBLIC_REGISTRATION_ENABLED"] == "false"


@pytest.mark.parametrize("spec", ["vault", "dir:", "file:", "consul:nope", "http:ftp://x"])
def test_parse_source_errors(spec: str) -> None:
    with pytest.raises(config.ConfigSourceError):
        parse_source(spec)

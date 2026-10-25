"""Pluggable configuration sources. Each returns flat key/value pairs in
canonical form (upper case, ``_`` separated); later sources override
earlier ones.

Implement ``Source`` to add a backend (Vault, etcd, GCP Secret Manager...).
A source should treat "no data" as an empty mapping, not an error, so
optional layers can be stacked.
"""

import asyncio
import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urlsplit, urlunsplit

import httpx

type Values = frozendict[str, str]

# Caps a single value read from disk or the network.
MAX_VALUE_BYTES: Final = 1 << 20
# Bounds every remote fetch so startup cannot hang.
REMOTE_TIMEOUT: Final = 10.0

_KEY_SEPARATORS: Final = str.maketrans({"-": "_", ".": "_", "/": "_"})


class ConfigSourceError(Exception):
    pass


class Source(Protocol):
    @property
    def name(self) -> str: ...

    async def load(self) -> Values: ...


def normalize_key(k: str) -> str:
    """ "database-url", "database.url" and "DATABASE_URL" all become "DATABASE_URL"."""
    return k.strip().translate(_KEY_SEPARATORS).upper()


@dataclass(frozen=True, slots=True)
class EnvSource:
    """The process environment. With a prefix, only variables starting with
    it are used and the prefix is stripped."""

    prefix: str = ""

    @property
    def name(self) -> str:
        return "env"

    async def load(self) -> Values:
        return frozendict(
            {
                normalize_key(k.removeprefix(self.prefix)): v
                for k, v in os.environ.items()
                if not self.prefix or k.startswith(self.prefix)
            }
        )


@dataclass(frozen=True, slots=True)
class DirSource:
    """One value per file, the file name being the key: the layout of
    Kubernetes ConfigMap/Secret volumes and Docker secrets (/run/secrets).
    Hidden entries are skipped, symlinks followed and one trailing newline
    trimmed. A missing directory yields no values."""

    path: str

    @property
    def name(self) -> str:
        return f"dir:{self.path}"

    async def load(self) -> Values:
        return await asyncio.to_thread(self._load)

    def _load(self) -> Values:
        root = Path(self.path)
        if not root.is_dir():
            return frozendict()
        out: dict[str, str] = {}
        for entry in sorted(root.iterdir()):
            if entry.name.startswith(".") or not entry.is_file():  # is_file follows symlinks
                continue
            if entry.stat().st_size > MAX_VALUE_BYTES:
                raise ConfigSourceError(f"{entry}: value larger than {MAX_VALUE_BYTES} bytes")
            value = entry.read_text(encoding="utf-8").removesuffix("\n").removesuffix("\r")
            out[normalize_key(entry.name)] = value
        return frozendict(out)


@dataclass(frozen=True, slots=True)
class DotenvSource:
    """KEY=VALUE lines, typically for local development. Blank lines, ``#``
    comments and an ``export`` prefix are ignored; values may be quoted. A
    missing file yields no values."""

    path: str

    @property
    def name(self) -> str:
        return f"file:{self.path}"

    async def load(self) -> Values:
        return await asyncio.to_thread(self._load)

    def _load(self) -> Values:
        p = Path(self.path)
        if not p.exists():
            return frozendict()
        with p.open(encoding="utf-8") as f:
            return parse_dotenv(f.read(MAX_VALUE_BYTES))


def parse_dotenv(text: str) -> Values:
    out: dict[str, str] = {}
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.removeprefix("export ").partition("=")
        if not sep:
            raise ConfigSourceError(f"line {n}: expected KEY=VALUE")
        value = value.strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            value = value[1:-1]
        out[normalize_key(key)] = value
    return frozendict(out)


@dataclass(frozen=True, slots=True)
class ConsulSource:
    """All keys under a prefix of Consul's KV store, over its HTTP API.
    "rbac-service/DATABASE_URL" becomes "DATABASE_URL"; nested folders are
    flattened with "_"."""

    address: str  # e.g. "https://consul.service:8501"
    prefix: str  # e.g. "rbac-service"
    token: str = field(default="", repr=False)  # ACL token, sent as X-Consul-Token
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False, compare=False)

    @property
    def name(self) -> str:
        return f"consul:{self.prefix}"

    async def load(self) -> Values:
        url = f"{self.address.rstrip('/')}/v1/kv/{self.prefix.strip('/')}"
        headers = {"X-Consul-Token": self.token} if self.token else {}
        status, body = await _fetch(url, headers, {"recurse": "true"}, self.transport)
        if status == 404:  # prefix has no keys yet
            return frozendict()
        if status != 200:
            raise ConfigSourceError(f"consul returned HTTP {status}")
        try:
            entries = json.loads(body)
        except ValueError as e:
            raise ConfigSourceError(f"decode consul response: {e}") from e
        out: dict[str, str] = {}
        for entry in entries:
            if entry.get("Value") is None:  # folder
                continue
            key = entry["Key"].removeprefix(self.prefix).removeprefix("/")
            if key:
                out[normalize_key(key)] = base64.b64decode(entry["Value"]).decode()
        return frozendict(out)


@dataclass(frozen=True, slots=True)
class HTTPJSONSource:
    """A flat JSON object ({"KEY": "value", ...}) from a URL. Works with the
    AWS AppConfig Agent (http://localhost:2772/applications/{app}/
    environments/{env}/configurations/{profile}), which handles AWS auth and
    caching, and with any config server that can serve JSON. Numbers and
    booleans are converted to strings."""

    url: str
    headers: frozendict[str, str] = field(default_factory=frozendict, repr=False)
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False, compare=False)

    @property
    def name(self) -> str:
        return f"http:{self.url}"

    async def load(self) -> Values:
        status, body = await _fetch(self.url, dict(self.headers), {}, self.transport)
        if status != 200:
            raise ConfigSourceError(f"HTTP {status}")
        try:
            doc = json.loads(body)
        except ValueError as e:
            raise ConfigSourceError(f"expected a flat JSON object: {e}") from e
        if not isinstance(doc, dict):
            raise ConfigSourceError("expected a flat JSON object")
        out: dict[str, str] = {}
        for k, v in doc.items():
            match v:
                case None:
                    continue
                case bool():
                    out[normalize_key(k)] = "true" if v else "false"
                case str() | int() | float():
                    out[normalize_key(k)] = str(v)
                case _:
                    raise ConfigSourceError(f"key {k}: nested values are not supported")
        return frozendict(out)


async def _fetch(
    url: str, headers: dict[str, str], params: dict[str, str], transport: httpx.AsyncBaseTransport | None
) -> tuple[int, bytes]:
    async with (
        httpx.AsyncClient(timeout=REMOTE_TIMEOUT, transport=transport) as client,
        client.stream("GET", url, headers=headers, params=params) as resp,
    ):
        body = bytearray()
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) > MAX_VALUE_BYTES:
                raise ConfigSourceError(f"{url}: response larger than {MAX_VALUE_BYTES} bytes")
        return resp.status_code, bytes(body)


def parse_source(spec: str) -> Source:
    """Builds a Source from a CLI spec:

    env                      process environment
    env:PREFIX_              environment, only keys with PREFIX_ (stripped)
    file:/path/.env          dotenv file
    dir:/etc/rbac/secrets    one file per key (Kubernetes / Docker secrets)
    consul:http://consul:8500/rbac-service   Consul KV prefix (token from CONSUL_HTTP_TOKEN)
    http:http://localhost:2772/applications/a/environments/e/configurations/p
    """
    kind, _, arg = spec.partition(":")
    match kind:
        case "env":
            return EnvSource(prefix=arg)
        case "file" if arg:
            return DotenvSource(arg)
        case "dir" if arg:
            return DirSource(arg)
        case "consul":
            u = urlsplit(arg)
            if not u.scheme or not u.netloc:
                raise ConfigSourceError(f"config source {spec!r}: expected consul:<scheme>://<host:port>/<prefix>")
            address = urlunsplit((u.scheme, u.netloc, "", "", ""))
            return ConsulSource(
                address=address, prefix=u.path.strip("/"), token=os.environ.get("CONSUL_HTTP_TOKEN", "")
            )
        case "http":
            if urlsplit(arg).scheme not in ("http", "https"):
                raise ConfigSourceError(f"config source {spec!r}: expected http:<http(s) URL>")
            return HTTPJSONSource(arg)
        case "file" | "dir":
            raise ConfigSourceError(f"config source {spec!r}: missing path")
        case _:
            raise ConfigSourceError(f"unknown config source {spec!r} (want env, file, dir, consul or http)")

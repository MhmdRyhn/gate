"""The rbac-service command line.

    rbac-service serve                 run the HTTP API (multi-process)
    rbac-service seed                  sync permissions, roles, public types
    rbac-service admin create          create an admin (password via prompt/stdin)
    rbac-service keys generate|public  manage JWT signing keys
    rbac-service config print          show effective config (secrets redacted)
    rbac-service maintenance purge-sessions
    rbac-service healthcheck           container health probe
    rbac-service version

The global option --config-source (repeatable) selects where configuration
is read from; later sources override earlier ones.
"""

import asyncio
import getpass
import json
import os
import sys
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

import httpx
import typer
import uvicorn

from gate import auth, config, logs, version
from gate.container import Container, cpu_count
from gate.logs import Logger
from gate.web.app import CONFIG_SOURCES_ENV, PURGE_INTERVAL_ENV

app = typer.Typer(
    name="rbac-service",
    help="Authentication and role-based access control service.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)
admin_app = typer.Typer(help="Administrative account tasks.", no_args_is_help=True)
keys_app = typer.Typer(help="Manage JWT signing keys.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect configuration.", no_args_is_help=True)
maintenance_app = typer.Typer(help="Periodic maintenance tasks (run from cron / a scheduler).", no_args_is_help=True)
app.add_typer(admin_app, name="admin")
app.add_typer(keys_app, name="keys")
app.add_typer(config_app, name="config")
app.add_typer(maintenance_app, name="maintenance")


class _State:
    sources: tuple[str, ...] = ("env",)


@app.callback()
def _global(
    config_source: Annotated[
        list[str] | None,
        typer.Option(
            help="Configuration source, repeatable; later wins. "
            "env | env:PREFIX_ | file:PATH | dir:PATH | consul:URL/PREFIX | http:URL"
        ),
    ] = None,
) -> None:
    _State.sources = tuple(config_source or ["env"])


def _fail(msg: str) -> typer.Exit:
    typer.echo(f"error: {msg}", err=True)
    return typer.Exit(1)


async def _load_config() -> config.Config:
    try:
        return await config.load([config.parse_source(s) for s in _State.sources])
    except (config.ConfigError, config.ConfigSourceError) as e:
        raise _fail(f"config: {e}") from None


def _with_container(fn: Callable[[Container, Logger], Awaitable[None]]) -> None:
    """Runs fn with the application services and releases them after."""

    async def run() -> None:
        cfg = await _load_config()
        log = logs.configure(cfg.log)
        async with Container.build(cfg, log).running() as c:
            await fn(c, log)

    try:
        asyncio.run(run())
    except typer.Exit:
        raise
    except Exception as e:
        raise _fail(str(e)) from None


@app.command()
def serve(
    sync_rbac: Annotated[bool, typer.Option(help="Sync permissions, default roles and public types on start.")] = True,
    workers: Annotated[int, typer.Option(help="Worker processes (default: HTTP_WORKERS, else one per CPU).")] = 0,
    purge_interval: Annotated[
        str, typer.Option(help="How often each worker deletes ended sessions (0 disables).")
    ] = "1h",
) -> None:
    """Run the HTTP API. The database schema must already be migrated (see /migrations)."""
    cfg = asyncio.run(_load_config())
    log = logs.configure(cfg.log)
    log.info("starting", version=version.VERSION, commit=version.COMMIT)
    if sync_rbac:
        _with_container(lambda c, _: c.seeder.sync())

    n = workers or cfg.http.workers or cpu_count()
    os.environ[CONFIG_SOURCES_ENV] = json.dumps(_State.sources)
    os.environ[PURGE_INTERVAL_ENV] = purge_interval
    h = cfg.http
    log.info("http server listening", addr=h.addr, workers=n)
    uvicorn.run(
        "gate.web.app:from_environment",
        factory=True,
        host=h.host,
        port=h.port,
        workers=n,
        loop="uvloop",
        http="httptools",
        lifespan="on",
        backlog=h.backlog,
        limit_concurrency=h.max_concurrency or None,
        timeout_keep_alive=int(h.idle_timeout.total_seconds()),
        timeout_graceful_shutdown=int(h.shutdown_timeout.total_seconds()),
        # Client IPs are resolved by GateMiddleware from HTTP_TRUSTED_PROXIES.
        proxy_headers=False,
        server_header=False,
        access_log=False,  # GateMiddleware logs each request
        log_config=None,
    )


@app.command()
def seed() -> None:
    """Sync permissions, default roles and public user types into the database."""
    _with_container(lambda c, _: c.seeder.sync())


def _read_password(from_stdin: bool) -> str:
    """Never a flag, so it cannot leak through shell history or the process list."""
    if from_stdin:
        return sys.stdin.read(4096).rstrip("\r\n")
    if not sys.stdin.isatty():
        raise _fail("no terminal: use --password-stdin")
    p1 = getpass.getpass("Password: ")
    if p1 != getpass.getpass("Repeat password: "):
        raise _fail("passwords do not match")
    return p1


@admin_app.command("create")
def admin_create(
    email: Annotated[str, typer.Option(help="Admin email.")] = "",
    phone: Annotated[str, typer.Option(help="Admin phone (E.164).")] = "",
    name: Annotated[str, typer.Option(help="Full name.")] = "Administrator",
    password_stdin: Annotated[bool, typer.Option(help="Read the password from stdin.")] = False,
) -> None:
    """Create an internal user with the admin role.

    The password is read from an interactive prompt, or from stdin with
    --password-stdin.
    """
    if not email and not phone:
        raise _fail("one of --email or --phone is required")
    password = _read_password(password_stdin)

    async def create(c: Container, _: Logger) -> None:
        await c.seeder.sync()
        u = await c.seeder.create_admin(email, phone, name, password)
        typer.echo(f"admin created: {u.id}")

    _with_container(create)


@keys_app.command("generate")
def keys_generate(
    type: Annotated[str, typer.Option(help="Key type: ed25519 (EdDSA) or rsa (RS256).")] = "ed25519",
    bits: Annotated[int, typer.Option(help="RSA key size.")] = 3072,
) -> None:
    """Generate a PKCS#8 private signing key (PEM on stdout, key ID on stderr)."""
    try:
        pem, kid = auth.generate_key(type, bits)
    except auth.InvalidKeyError as e:
        raise _fail(str(e)) from None
    sys.stdout.write(pem)
    typer.echo(f"kid: {kid}", err=True)


@keys_app.command("public")
def keys_public() -> None:
    """Print the public key of a private key read from stdin (for JWT_VERIFICATION_KEYS)."""
    try:
        sys.stdout.write(auth.public_key_pem(sys.stdin.read(64 << 10)))
    except auth.InvalidKeyError as e:
        raise _fail(str(e)) from None


@config_app.command("print")
def config_print() -> None:
    """Validate and print the effective configuration (secrets redacted)."""
    typer.echo(config.to_json(asyncio.run(_load_config())))


@maintenance_app.command("purge-sessions")
def purge_sessions(
    older_than: Annotated[str, typer.Option(help="Grace period after a session ended.")] = "24h",
) -> None:
    """Delete sessions and refresh tokens that ended before now minus --older-than."""
    grace = config.parse_duration(older_than)

    async def purge(c: Container, log: Logger) -> None:
        n = await c.auth.purge_sessions(datetime.now(UTC) - grace)
        log.info("purged ended sessions", rows=n)

    _with_container(purge)


@app.command()
def healthcheck(
    url: Annotated[str, typer.Option(help="Health URL (default http://127.0.0.1:<HTTP_ADDR port>/healthz).")] = "",
) -> None:
    """Probe the local /healthz endpoint (exit 0 when healthy); for container HEALTHCHECK."""
    if not url:
        port = os.environ.get("HTTP_ADDR", ":8080").rpartition(":")[2] or "8080"
        url = f"http://127.0.0.1:{port}/healthz"
    try:
        status = httpx.get(url, timeout=3).status_code
    except httpx.HTTPError as e:
        raise _fail(str(e)) from None
    if status != 200:
        raise _fail(f"unhealthy: HTTP {status}")


@app.command("version")
def version_cmd() -> None:
    """Print build information."""
    typer.echo(f"rbac-service {version.VERSION} (commit {version.COMMIT}, built {version.BUILD_DATE})")


def _hoist_global_options(argv: list[str]) -> list[str]:
    """Lets --config-source appear anywhere, like a persistent flag: moves
    every occurrence in front of the subcommand."""
    hoisted: list[str] = []
    rest: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--config-source" and i + 1 < len(argv):
            hoisted += argv[i : i + 2]
            i += 2
            continue
        (hoisted if arg.startswith("--config-source=") else rest).append(arg)
        i += 1
    return hoisted + rest


def main() -> None:
    app(args=_hoist_global_options(sys.argv[1:]), prog_name="rbac-service")

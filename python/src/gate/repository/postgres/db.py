"""SQLAlchemy Core on the asyncpg driver. The schema is managed outside the
application (see /migrations); this package never runs DDL.

SQLAlchemy owns the schema definitions (tables.py), every query (Core
expressions), the connection pool, connection recycling and transactions.
Choices that keep its overhead close to raw asyncpg (measured: about 40 µs
of CPU per query for raw asyncpg, 68 µs through ``Connection.execute``, 45 µs
with the fast path below):

- Core, not the ORM: no identity map, unit of work or lazy loading. Rows map
  straight into frozen domain dataclasses.
- **Prepared statements** (``prepare()``): static queries, which include
  every query on the hot paths (authentication, login, refresh, /me), are
  compiled ONCE at import into PostgreSQL SQL. Executing one only binds
  positional parameters and runs it on the asyncpg connection of a pooled
  SQLAlchemy connection, skipping SQLAlchemy's per-execution work
  (cache-key generation, greenlet hop, result-row construction).
- Dynamic queries (optional filters, partial updates) go through the normal
  ``Connection.execute`` and SQLAlchemy's compiled-statement cache.
- AUTOCOMMIT is the engine default, so a single statement costs one round
  trip, not three (BEGIN / query / ROLLBACK), and a checkout changes no
  connection state. ``transaction()`` opens a real (asyncpg) transaction
  for multi-statement writes.
- asyncpg prepares each SQL text once per connection and reuses it.
- No pre-ping (an extra round trip per checkout); connections that fail are
  invalidated and replaced.
"""

import asyncio
import functools
import time
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Final

import asyncpg
from sqlalchemy import Executable, text
from sqlalchemy.dialects.postgresql.asyncpg import dialect as asyncpg_dialect
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.sql import ClauseElement
from sqlalchemy.sql.compiler import SQLCompiler

from gate.config import DatabaseConfig
from gate.domain import ConflictError
from gate.logs import Logger

# An asyncpg Record or a SQLAlchemy RowMapping: both are read by column name.
type Record = Mapping[Any, Any]
type Params = Mapping[str, Any]

_MAX_BACKOFF: Final = 10.0
_DIALECT: Final = asyncpg_dialect()  # type: ignore[no-untyped-call]
# Errors after which a pooled connection must not be reused.
_BROKEN: Final = (asyncpg.ConnectionDoesNotExistError, asyncpg.InterfaceError, OSError)


@dataclass(frozen=True, slots=True)
class Prepared:
    """A Core statement compiled once to PostgreSQL SQL with positional
    parameters. Parameters are bound by name; literal values written into
    the statement are kept as defaults."""

    sql: str
    names: tuple[str, ...]
    defaults: frozendict[str, Any]

    def args(self, params: Params) -> tuple[Any, ...]:
        return tuple(params[n] if n in params else self.defaults[n] for n in self.names)


def prepare(stmt: ClauseElement) -> Prepared:
    """Compiles a static statement once. Bind parameter names must not equal
    column names of an UPDATE/INSERT target: SQLAlchemy would treat them as
    values to assign. The repositories prefix them with ``p_``."""
    compiled = stmt.compile(dialect=_DIALECT)
    assert isinstance(compiled, SQLCompiler)
    return Prepared(
        sql=str(compiled),
        names=tuple(compiled.positiontup or ()),
        defaults=frozendict({k: v for k, v in compiled.params.items() if v is not None}),
    )


def _conflict(sqlstate: str | None) -> ConflictError | None:
    match sqlstate:
        case "23505":  # unique_violation
            return ConflictError("already exists")
        case "23503":  # foreign_key_violation
            return ConflictError("still referenced or references a missing record")
        case _:
            return None


def affected(status: str) -> int:
    """Row count of a command status such as "UPDATE 3" or "DELETE 0"."""
    return int(status.rsplit(" ", 1)[-1])


def _engine(cfg: DatabaseConfig) -> AsyncEngine:
    connect = functools.partial(
        asyncpg.connect,
        # The DSN goes to asyncpg unchanged, so libpq-style options such as
        # ?sslmode=verify-full&sslrootcert=... keep working.
        cfg.url.reveal(),
        timeout=5,
        command_timeout=cfg.statement_timeout.total_seconds() + 5,
        statement_cache_size=cfg.statement_cache_size,
        server_settings={
            "statement_timeout": str(int(cfg.statement_timeout.total_seconds() * 1000)),
            "application_name": "rbac-service",
            "timezone": "UTC",
        },
    )
    engine: AsyncEngine

    def creator() -> Any:
        # Equivalent of create_async_engine(async_creator=...), but also
        # sizes SQLAlchemy's own prepared statement cache.
        return engine.sync_engine.dialect.dbapi.connect(  # type: ignore[union-attr]
            async_creator_fn=connect, prepared_statement_cache_size=cfg.statement_cache_size
        )

    engine = create_async_engine(
        "postgresql+asyncpg://",
        creator=creator,
        pool_size=cfg.max_open_conns,
        max_overflow=0,
        pool_timeout=cfg.pool_timeout.total_seconds(),
        pool_recycle=int(cfg.conn_max_lifetime.total_seconds()),
        pool_pre_ping=False,
        pool_use_lifo=True,  # idle connections age out of use under low load
        isolation_level="AUTOCOMMIT",
    )
    return engine


async def driver(conn: AsyncConnection) -> asyncpg.Connection:
    """The asyncpg connection behind a SQLAlchemy connection. Inside
    ``transaction()`` it takes part in the same transaction."""
    raw = await conn.get_raw_connection()
    return raw.driver_connection


class Database:
    """Owns the engine. Repositories are built before it connects (the
    application is assembled synchronously) and borrow connections from it
    afterwards. Every method maps constraint violations to ConflictError
    and logs statements slower than DB_SLOW_QUERY_THRESHOLD."""

    __slots__ = ("_cfg", "_engine", "_log", "_slow")

    def __init__(self, cfg: DatabaseConfig, log: Logger) -> None:
        self._cfg: Final = cfg
        self._log: Final = log
        self._slow: Final = cfg.slow_query_threshold.total_seconds()
        self._engine: AsyncEngine | None = None

    def _require(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("database is not connected")
        return self._engine

    async def connect(self) -> None:
        """Creates the engine and opens DB_MAX_IDLE_CONNS connections,
        retrying with exponential backoff up to DB_CONNECT_TIMEOUT, so the
        service tolerates starting before its database."""
        cfg = self._cfg
        engine = _engine(cfg)
        deadline = time.monotonic() + cfg.connect_timeout.total_seconds()
        wait = 0.5
        while True:
            try:
                await self._warm_up(engine, max(1, cfg.max_idle_conns))
                break
            except (OSError, DBAPIError, TimeoutError) as e:
                if time.monotonic() + wait > deadline:
                    await engine.dispose()
                    raise RuntimeError(f"database not reachable within {cfg.connect_timeout}: {e}") from e
                self._log.warning("database not reachable, retrying", error=str(e), retry_in=wait)
                await asyncio.sleep(wait)
                wait = min(wait * 2, _MAX_BACKOFF)
        self._engine = engine

    @staticmethod
    async def _warm_up(engine: AsyncEngine, n: int) -> None:
        conns = [await engine.connect() for _ in range(n)]
        try:
            await conns[0].execute(text("SELECT 1"))
        finally:
            for c in conns:
                await c.close()

    async def close(self) -> None:
        if self._engine is not None:
            await asyncio.wait_for(self._engine.dispose(), timeout=10)
            self._engine = None

    async def ping(self) -> None:
        """Implements HealthChecker."""
        async with asyncio.timeout(2), self._connection("ping") as conn:
            await (await driver(conn)).fetchval("SELECT 1")

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncConnection]:
        """A connection inside a transaction, committed when the block exits
        normally and rolled back on any exception. Use the ``tx_*`` methods
        (or ``conn.execute``) inside it.

        The transaction is asyncpg's, on the driver connection: SQLAlchemy's
        adapter would send BEGIN only on its own first execute, so statements
        on the fast path would escape a SQLAlchemy transaction. The pooled
        connection stays in AUTOCOMMIT, so SQLAlchemy adds no BEGIN of its
        own and its executes on this connection join the same transaction."""
        async with self._connection("transaction") as conn, (await driver(conn)).transaction():
            yield conn

    # --- prepared statements: the fast path --------------------------------------

    async def fetch(self, p: Prepared, params: Params | None = None) -> list[Record]:
        result: list[Record] = await self._fast(asyncpg.Connection.fetch, p, params)
        return result

    async def fetchrow(self, p: Prepared, params: Params | None = None) -> Record | None:
        row: Record | None = await self._fast(asyncpg.Connection.fetchrow, p, params)
        return row

    async def run(self, p: Prepared, params: Params | None = None) -> int:
        """Runs a write; returns the number of rows affected."""
        return affected(await self._fast(asyncpg.Connection.execute, p, params))

    async def _fast(self, op: Callable[..., Awaitable[Any]], p: Prepared, params: Params | None) -> Any:
        """One pooled checkout and one driver call. Written out inline
        (rather than with the context managers below) because it runs for
        nearly every query: each generator-based context manager costs a
        few microseconds."""
        engine = self._require()
        start = time.perf_counter()
        try:
            async with engine.connect() as conn:
                raw = await conn.get_raw_connection()
                try:
                    return await op(raw.driver_connection, p.sql, *p.args(params or {}))
                except _BROKEN:
                    await conn.invalidate()  # never hand a dead connection out again
                    raise
        except asyncpg.IntegrityConstraintViolationError as e:
            raise _conflict(e.sqlstate) or e from e
        finally:
            if time.perf_counter() - start > self._slow:
                self._log_slow(p.sql, start)

    @staticmethod
    async def tx_fetchval(tx: AsyncConnection, p: Prepared, params: Params | None = None) -> Any:
        return await (await driver(tx)).fetchval(p.sql, *p.args(params or {}))

    @staticmethod
    async def tx_run(tx: AsyncConnection, p: Prepared, params: Params | None = None) -> int:
        return affected(await (await driver(tx)).execute(p.sql, *p.args(params or {})))

    @staticmethod
    async def tx_run_many(tx: AsyncConnection, p: Prepared, rows: Iterable[Params]) -> None:
        await (await driver(tx)).executemany(p.sql, [p.args(r) for r in rows])

    # --- dynamic statements: SQLAlchemy's normal execution -----------------------

    async def all(self, stmt: Executable, params: Params | None = None) -> Sequence[Record]:
        async with self._connection(stmt) as conn:
            return (await conn.execute(stmt, params)).mappings().all()

    async def execute(self, stmt: Executable, params: Params | None = None) -> int:
        """Runs a write; returns the number of rows affected."""
        async with self._connection(stmt) as conn:
            return (await conn.execute(stmt, params)).rowcount

    # --- plumbing ----------------------------------------------------------------

    @asynccontextmanager
    async def _connection(self, what: object) -> AsyncGenerator[AsyncConnection]:
        engine = self._require()
        async with self._guard(what), engine.connect() as conn:
            try:
                yield conn
            except _BROKEN:
                await conn.invalidate()  # never hand a dead connection out again
                raise

    @asynccontextmanager
    async def _guard(self, what: object) -> AsyncGenerator[None]:
        start = time.perf_counter()
        try:
            yield
        except IntegrityError as e:
            raise _conflict(getattr(e.orig, "sqlstate", None)) or e from e
        except asyncpg.IntegrityConstraintViolationError as e:
            raise _conflict(e.sqlstate) or e from e
        finally:
            if time.perf_counter() - start > self._slow:
                self._log_slow(what, start)

    def _log_slow(self, what: object, start: float) -> None:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        self._log.warning("slow query", query=" ".join(str(what).split())[:200], elapsed_ms=elapsed_ms)

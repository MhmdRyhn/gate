"""Structured logging with structlog. JSON output (the default) is meant
for log shippers; console output for local development."""

import logging
import sys
from typing import Final

import structlog

from gate.config import LogConfig

type Logger = structlog.typing.FilteringBoundLogger

_LEVELS: Final = frozendict(
    {"debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}
)


def configure(cfg: LogConfig) -> Logger:
    renderer: structlog.typing.Processor = (
        structlog.dev.ConsoleRenderer() if cfg.format == "console" else structlog.processors.JSONRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="time"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        # The filtering logger drops disabled levels before any processing.
        wrapper_class=structlog.make_filtering_bound_logger(_LEVELS[cfg.level]),
        logger_factory=structlog.WriteLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    # Libraries using the stdlib logging module (uvicorn, asyncpg) log at
    # the same level.
    logging.basicConfig(level=_LEVELS[cfg.level], stream=sys.stdout, format="%(levelname)s %(name)s %(message)s")
    logger: Logger = structlog.get_logger()
    return logger

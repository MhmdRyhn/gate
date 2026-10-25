"""The SQLAlchemy table definitions must match the schema owned by
../migrations: every table and column used by the queries must exist."""

import re
from pathlib import Path

from gate.repository.postgres.tables import metadata

MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations"
_TABLE = re.compile(r"CREATE TABLE (\w+) \((.*?)\n\);", re.DOTALL)
_COLUMN = re.compile(r"^\s+(\w+)\s+(?!KEY|CHECK)\w", re.MULTILINE)
_NOT_COLUMNS = {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"}


def schema() -> dict[str, set[str]]:
    sql = "\n".join(p.read_text() for p in sorted(MIGRATIONS.glob("*.up.sql")))
    return {
        name: {c for c in _COLUMN.findall(body) if c.upper() not in _NOT_COLUMNS} for name, body in _TABLE.findall(sql)
    }


def test_tables_match_migrations() -> None:
    db = schema()
    assert db, "no CREATE TABLE found in migrations"
    for table in metadata.sorted_tables:
        assert table.name in db, f"table {table.name} is not in the migrations"
        assert {c.name for c in table.columns} == db[table.name], f"columns of {table.name} differ from the migration"
    assert {t.name for t in metadata.sorted_tables} == set(db), "a migrated table has no definition"

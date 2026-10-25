from dataclasses import dataclass, field
from typing import Final

_REDACTED: Final = "[REDACTED]"


@dataclass(frozen=True, slots=True, repr=False)
class Secret:
    """A string that never reveals its value when printed, logged or
    serialised. Call ``reveal()`` to obtain the plaintext deliberately."""

    _value: str = field(default="")

    def reveal(self) -> str:
        return self._value

    @property
    def is_set(self) -> bool:
        return self._value != ""

    def masked(self) -> str:
        return _REDACTED if self._value else ""

    def __repr__(self) -> str:
        return f"Secret({self.masked()!r})"

    def __str__(self) -> str:
        return self.masked()

    def __format__(self, spec: str) -> str:
        return format(self.masked(), spec)

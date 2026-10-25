"""Build metadata. The Docker build writes these through environment
variables (GATE_VERSION, GATE_COMMIT, GATE_BUILD_DATE)."""

import os
from typing import Final

VERSION: Final = os.environ.get("GATE_VERSION", "dev")
COMMIT: Final = os.environ.get("GATE_COMMIT", "unknown")
BUILD_DATE: Final = os.environ.get("GATE_BUILD_DATE", "unknown")

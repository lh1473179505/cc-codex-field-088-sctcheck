"""Load a certificate-transparency snapshot, a frozen log list policy, and log keys."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
class LoadError(Exception):
    pass
def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(str(exc)) from exc

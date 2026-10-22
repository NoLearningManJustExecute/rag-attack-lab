"""Canary values for the fictional internal documents.

The committed documents in data/internal/ hold placeholders such as {{CANARY:DBPASS}}, never a value.
At ingest time each placeholder is replaced with a value generated on this machine, for example
RAL-CANARY-DBPASS-3F9A1C2E7B4D. The values are saved to settings.canary_file (git-ignored), so
ingesting again reuses them and a leaked value can be matched back to the canary it came from.

Every value uses the obviously fake RAL-CANARY-... format. None of them is a real credential, and
none of them looks like a real provider key.
"""

import json
import re
import secrets
from pathlib import Path

from rag_attack_lab.config import Settings

CANARY_PREFIX = "RAL-CANARY"
PLACEHOLDER = re.compile(r"\{\{CANARY:([A-Z0-9_]+)\}\}")


def make_canary(name: str) -> str:
    """A fresh value for the canary `name`, for example RAL-CANARY-DBPASS-3F9A1C2E7B4D."""
    return f"{CANARY_PREFIX}-{name}-{secrets.token_hex(6).upper()}"


def load_canaries(path: Path) -> dict[str, str]:
    """Read the saved canary values. An absent file means none have been generated yet."""
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_canaries(path: Path, canaries: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(canaries, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fill_canaries(text: str, settings: Settings) -> str:
    """Replace every {{CANARY:NAME}} placeholder in `text` with its value, generating any that are new."""
    names = PLACEHOLDER.findall(text)
    if not names:
        return text

    canaries = load_canaries(settings.canary_file)
    new_names = [name for name in names if name not in canaries]
    for name in new_names:
        canaries[name] = make_canary(name)
    if new_names:
        save_canaries(settings.canary_file, canaries)

    return PLACEHOLDER.sub(lambda match: canaries[match.group(1)], text)

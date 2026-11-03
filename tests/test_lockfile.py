"""The lockfile must agree with the direct pins in the requirements files."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PIN = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;]+)", re.MULTILINE)


def pins(name):
    text = (REPO_ROOT / name).read_text(encoding="utf-8")
    return {re.sub(r"[-_.]+", "-", package).lower(): version for package, version in PIN.findall(text)}


def test_every_direct_pin_is_in_the_lockfile():
    lock = pins("requirements-lock.txt")
    direct = pins("requirements.txt") | pins("requirements-dev.txt")
    assert direct
    assert {name: lock.get(name) for name in direct} == direct

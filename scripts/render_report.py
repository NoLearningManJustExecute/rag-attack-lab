"""Render docs/report/pentest-report.md to PDF with a local Chromium browser (Edge or Chrome).

Markdown becomes HTML with markdown-it-py (installed with rich, already in requirements.txt), then
the browser prints the HTML to PDF in headless mode. Nothing is fetched from the network: the
stylesheet is inline and the page has no external links to load.

Usage, from the repo root:

    python scripts/render_report.py
    python scripts/render_report.py --browser "C:/path/to/chrome.exe"

Without --browser the script looks for msedge or chrome on PATH, then in the usual Windows
install folders. If none is found it says so and exits; you can also open the markdown in any
editor and export it to PDF by hand.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from markdown_it import MarkdownIt

SOURCE = Path("docs") / "report" / "pentest-report.md"
TARGET = Path("docs") / "report" / "pentest-report.pdf"

# Usual install folders on Windows, checked after PATH.
BROWSER_CANDIDATES = [
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
]

STYLE = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.5pt; line-height: 1.45; color: #1a1a1a; }
h1 { font-size: 20pt; margin: 0 0 8pt; }
h2 { font-size: 14pt; margin: 18pt 0 6pt; border-bottom: 1px solid #ccc; padding-bottom: 2pt; }
h3 { font-size: 12pt; margin: 14pt 0 4pt; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9.5pt; page-break-inside: avoid; }
th, td { border: 1px solid #bbb; padding: 3pt 6pt; text-align: left; vertical-align: top; }
th { background: #f0f0f0; }
code { font-family: Consolas, monospace; font-size: 9pt; background: #f4f4f4; padding: 0 2pt; }
pre { background: #f4f4f4; border: 1px solid #ddd; padding: 6pt; white-space: pre-wrap; word-break: break-word; }
pre code { background: none; padding: 0; }
blockquote { margin: 6pt 0; padding: 2pt 10pt; border-left: 3px solid #bbb; color: #333; }
"""


def find_browser(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    for name in ("msedge", "chrome"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return next((path for path in BROWSER_CANDIDATES if path.exists()), None)


def to_html(markdown: str) -> str:
    body = MarkdownIt("commonmark").enable("table").render(markdown)
    return f'<!doctype html><html><head><meta charset="utf-8"><style>{STYLE}</style></head><body>{body}</body></html>'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--browser", help="Path to msedge.exe or chrome.exe.")
    args = parser.parse_args()

    browser = find_browser(args.browser)
    if browser is None or not browser.exists():
        print("No Edge or Chrome found. Pass --browser, or export docs/report/pentest-report.md to PDF by hand.")
        return 1

    TARGET.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="report-", ignore_cleanup_errors=True) as work_dir:
        html_path = Path(work_dir) / "pentest-report.html"
        html_path.write_text(to_html(SOURCE.read_text(encoding="utf-8")), encoding="utf-8")
        command = [
            str(browser),
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--user-data-dir={Path(work_dir) / 'profile'}",
            f"--print-to-pdf={TARGET.resolve()}",
            html_path.resolve().as_uri(),
        ]
        subprocess.run(command, check=True, capture_output=True, timeout=120)
        # Edge's launcher can return before the browser has written the file, so wait for it.
        if not wait_for_file(TARGET):
            print(f"The browser exited but {TARGET} was not written. Try --browser with Chrome.")
            return 1

    print(f"Wrote {TARGET} ({TARGET.stat().st_size} bytes)")
    return 0


def wait_for_file(path: Path, timeout: float = 60.0) -> bool:
    """Wait until `path` exists and its size has stopped changing."""
    deadline = time.monotonic() + timeout
    last_size = -1
    while time.monotonic() < deadline:
        if path.exists():
            size = path.stat().st_size
            if size > 0 and size == last_size:
                return True
            last_size = size
        time.sleep(0.5)
    return False


if __name__ == "__main__":
    sys.exit(main())

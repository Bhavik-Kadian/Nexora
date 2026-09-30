"""Build a PDF of every page in docs/ (make docs-pdf).

The Markdown files stay the source: GitHub shows them and the gates scan them for secrets
(Gitleaks skips PDFs). Each page becomes HTML styled with the dashboard's design tokens, and
headless Microsoft Edge (or Chrome) prints it to docs/pdf/<name>.pdf. The one Mermaid diagram
is drawn first, with Mermaid loaded from a pinned address and checked against a pinned hash, so
only that step needs the internet. docs/pdf/manifest.json records which version of each page
its PDF was built from: only changed pages are rebuilt, and a test fails when a PDF is stale.
"""

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = DOCS / "pdf"
MANIFEST = OUT / "manifest.json"
TOKENS_CSS = ROOT / "src" / "securegate" / "ui" / "static" / "css" / "tokens.css"
PRINT_CSS = Path(__file__).with_name("docs_pdf.css")

MERMAID_URL = "https://cdn.jsdelivr.net/npm/mermaid@12.0.0/dist/mermaid.min.js"
MERMAID_SRI = "sha384-xzghz1GQ5u9HCpVskeDPqMsdogD1yvuMQbEK53+wi+G70+6J1AG0L2cfi9PHjDWI"
BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge",
    "microsoft-edge",
    "google-chrome",
    "chromium",
    "chromium-browser",
)

# Links to other pages: [Testing](testing.md) becomes "Testing (testing.pdf)". A clickable
# link would turn into an absolute file:// address on this computer, broken everywhere else.
PAGE_LINK = re.compile(r'<a href="(?![a-z]+:|#)([^"#]+)\.md(?:#[^"]*)?">(.*?)</a>', re.DOTALL)
MERMAID_BLOCK = re.compile(r'<pre><code class="language-mermaid">(.*?)</code></pre>', re.DOTALL)
SVG = re.compile(r"<svg\b.*?</svg>", re.DOTALL)


def source_hash(page: Path) -> str:
    return hashlib.sha256(page.read_bytes()).hexdigest()


def page_parts(text: str) -> tuple[str, str, list[str]]:
    """The page's title, its HTML body, and the source of each Mermaid diagram in it."""
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists"])
    body = PAGE_LINK.sub(
        lambda m: f'{m.group(2)} <span class="page-ref">({m.group(1)}.pdf)</span>', body
    )
    diagrams = [html.unescape(block) for block in MERMAID_BLOCK.findall(body)]
    title = next(
        (line[2:].strip() for line in text.splitlines() if line.startswith("# ")), "SecureGate"
    )
    return title, body, diagrams


def with_diagrams(body: str, svgs: list[str]) -> str:
    """Put the drawn diagrams where their Mermaid source was."""
    drawings = iter(svgs)
    return MERMAID_BLOCK.sub(lambda _: f'<figure class="diagram">{next(drawings)}</figure>', body)


def document(title: str, body: str) -> str:
    style = TOKENS_CSS.read_text(encoding="utf-8") + PRINT_CSS.read_text(encoding="utf-8")
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>{html.escape(title)}</title><style>{style}</style></head>"
        f"<body>{body}</body></html>"
    )


def find_browser() -> str:
    for candidate in BROWSERS:
        found = candidate if Path(candidate).is_file() else shutil.which(candidate)
        if found:
            return found
    sys.exit("docs-pdf needs Microsoft Edge or Google Chrome (headless). None was found.")


def run_browser(browser: str, profile: Path, *args: str) -> str:
    done = subprocess.run(  # noqa: S603 - a local browser with arguments built here
        [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--disable-extensions",
            f"--user-data-dir={profile}",
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    if done.returncode != 0:
        sys.exit(f"the browser failed (exit code {done.returncode}): {done.stderr[-500:]}")
    return done.stdout


def draw_diagrams(diagrams: list[str], browser: str, work: Path) -> list[str]:
    """Let Mermaid draw each diagram in the browser, and return the drawings as SVG."""
    blocks = "".join(f'<pre class="mermaid">{html.escape(d)}</pre>' for d in diagrams)
    page = work / "diagrams.html"
    page.write_text(
        f'<!doctype html><html><head><meta charset="utf-8"></head><body>{blocks}'
        f'<script src="{MERMAID_URL}" integrity="{MERMAID_SRI}" crossorigin="anonymous">'
        "</script><script>mermaid.initialize({startOnLoad: false, theme: 'neutral', "
        "themeVariables: {fontFamily: '\"Segoe UI\", system-ui, sans-serif'}}); "
        "mermaid.run();</script></body></html>",
        encoding="utf-8",
    )
    dom = run_browser(
        browser, work / "profile", "--virtual-time-budget=30000", "--dump-dom", page.as_uri()
    )
    svgs = SVG.findall(dom)
    if len(svgs) != len(diagrams):
        sys.exit(
            "could not draw the Mermaid diagram: the internet is needed to load Mermaid "
            f"from {MERMAID_URL}"
        )
    return svgs


def build(page: Path, browser: str, work: Path) -> Path:
    title, body, diagrams = page_parts(page.read_text(encoding="utf-8"))
    if diagrams:
        body = with_diagrams(body, draw_diagrams(diagrams, browser, work))
    source = work / f"{page.stem}.html"
    source.write_text(document(title, body), encoding="utf-8")
    target = OUT / f"{page.stem}.pdf"
    run_browser(
        browser,
        work / "profile",
        "--no-pdf-header-footer",
        f"--print-to-pdf={target}",
        source.as_uri(),
    )
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build docs/pdf/*.pdf from docs/*.md.")
    parser.add_argument("--force", action="store_true", help="rebuild every PDF")
    args = parser.parse_args(argv)
    OUT.mkdir(exist_ok=True)
    built = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    pages = sorted(DOCS.glob("*.md"))
    manifest = {page.name: source_hash(page) for page in pages}
    browser = find_browser()
    with tempfile.TemporaryDirectory(prefix="securegate-docs-") as scratch:
        for page in pages:
            pdf = OUT / f"{page.stem}.pdf"
            if not args.force and pdf.exists() and built.get(page.name) == manifest[page.name]:
                print(f"up to date  {pdf.relative_to(ROOT).as_posix()}")
                continue
            build(page, browser, Path(scratch))
            print(f"built       {pdf.relative_to(ROOT).as_posix()}")
    for orphan in sorted(set(OUT.glob("*.pdf")) - {OUT / f"{p.stem}.pdf" for p in pages}):
        orphan.unlink()
        print(f"removed     {orphan.relative_to(ROOT).as_posix()} (its page is gone)")
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

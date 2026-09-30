"""The PDF copies of docs/: how pages are converted, and that every PDF is up to date."""

import hashlib
import importlib.util
import json

from helpers import REPO_ROOT

DOCS = REPO_ROOT / "docs"
PDFS = DOCS / "pdf"


def load_builder():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("docs_pdf", REPO_ROOT / "tools" / "docs_pdf.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUILDER = load_builder()


# --- converting a page --------------------------------------------------------------------

PAGE = """# Sample page

See [Testing](testing.md), [a section](glossary.md#secret) and [GitHub](https://github.com).

| Decision | Meaning |
|---|---|
| block | stop |

```mermaid
flowchart LR
    A["Find"] --> B["Decide"]
```
"""


def test_title_comes_from_the_first_heading() -> None:
    title, _, _ = BUILDER.page_parts(PAGE)
    assert title == "Sample page"


def test_links_to_other_pages_name_the_pdf_instead() -> None:
    _, body, _ = BUILDER.page_parts(PAGE)
    assert 'Testing <span class="page-ref">(testing.pdf)</span>' in body
    assert 'a section <span class="page-ref">(glossary.pdf)</span>' in body
    assert '<a href="https://github.com">GitHub</a>' in body  # outside links stay links
    assert ".md" not in body


def test_tables_become_html_tables() -> None:
    _, body, _ = BUILDER.page_parts(PAGE)
    assert "<table>" in body and "<th>Decision</th>" in body and "<td>block</td>" in body


def test_mermaid_diagrams_are_found_and_replaced_by_drawings() -> None:
    _, body, diagrams = BUILDER.page_parts(PAGE)
    assert diagrams == ['flowchart LR\n    A["Find"] --> B["Decide"]\n']
    drawn = BUILDER.with_diagrams(body, ["<svg>drawing</svg>"])
    assert '<figure class="diagram"><svg>drawing</svg></figure>' in drawn
    assert "language-mermaid" not in drawn


# --- the committed PDFs ---------------------------------------------------------------------


def test_every_page_has_an_up_to_date_pdf() -> None:
    pages = sorted(DOCS.glob("*.md"))
    manifest = json.loads((PDFS / "manifest.json").read_text(encoding="utf-8"))
    stale = [
        page.name
        for page in pages
        if manifest.get(page.name) != hashlib.sha256(page.read_bytes()).hexdigest()
        or not (PDFS / f"{page.stem}.pdf").read_bytes().startswith(b"%PDF-")
    ]
    assert stale == [], f"out of date: {stale}. Run `make docs-pdf` and commit docs/pdf/."


def test_no_pdf_is_left_without_its_page() -> None:
    pdfs = {pdf.stem for pdf in PDFS.glob("*.pdf")}
    pages = {page.stem for page in DOCS.glob("*.md")}
    assert pdfs == pages

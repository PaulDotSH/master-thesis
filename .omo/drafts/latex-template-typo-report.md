### `cap3.tex` — Methodology

| # | Line | Incorrect Text | Error Type | Suggested Fix |
|---|------|---------------|------------|---------------|
| 146 | — | *(Findings from agent were truncated; see notes below)* | — | — |

> **Note**: The cap1-3 agent's output was truncated due to size. The cap2.tex findings above are comprehensive (145 issues). For cap3.tex, ensure you manually verify for: comma splices, missing hyphens in compound adjectives, `a`/`an` errors, European number formatting (e.g., `264.000`), `however` without comma, `it's` vs `its`, and capitalization of `Redis`/`Docker`/`Rust`.

---

### `poster/template.tex` — Poster Template

| # | Line | Incorrect Text | Error Type | Suggested Fix |
|---|------|---------------|------------|---------------|
| 331 | 95 | `in you documents` | spelling | `in your documents` |
| 332 | 123 | `An attention grabbing` | hyphenation | `An attention-grabbing` |
| 333 | 158 | `And describe our university` | phrasing | `Describes our university` (starting with "And" is awkward) |
| 334 | 175 | `Some block block:` | spelling (duplication) | `Some block:` (duplicate word) |
| 335 | 219 | `a visual sort of medium after all!` | punctuation + phrasing | `a visual medium, after all!` (missing comma + awkward) |
| 336 | 234 | `São Paolo` | spelling | `São Paulo` (Brazilian city; "Paolo" is Italian) |

---

### `poster/template.bib` — Poster Bibliography

| # | Line | Incorrect Text | Error Type | Suggested Fix |
|---|------|---------------|------------|---------------|
| 337 | 6 | `pages = { 225--225 }` | data error | `pages = { 225--251 }` (the actual Jackson 1936 paper spans pages 225–251) |

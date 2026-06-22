# Draft: LaTeX Typosweep

## Requirements (confirmed)
- Scan LaTeX + .bib files under master-thesis folder for typos
- Output: a markdown report listing typo, line number, and file path
- Hard constraint: DO NOT modify any LaTeX/bib source files
- User mentioned "use ultraworkers"

## Scope findings (research)
- 16 .tex files + 2 .bib files under `latex-template/`
- Largest: cap7.tex (~960 lines), cap2.tex (387 lines), main_file_template (~236 lines)
- All content is English (Rust supply-chain security thesis)
- Contains technical jargon: package names (Sim1h, holochain_core_types), API names (crates.io, Cargo.lock, build.rs), algorithm names (Levenshtein, Damerau-Levenshtein, Jaro-Winkler)

## Technical Decisions
- (pending) What counts as a "typo"
- (pending) How to treat technical jargon / package directory names
- (pending) Output markdown file path

## Open Questions
- Scope of "typo" — spelling only, or also grammar/punctuation?
- How to handle Rust/cargo/crate jargon (avoid false positives)?
- Where to save the report (e.g., `typos-report.md` repo root vs `.omo/`)?

## Scope Boundaries
- INCLUDE: all 18 .tex/.bib files in latex-template/ + poster/
- EXCLUDE: modifying any LaTeX/bib source files
## Feedback Item 12: Section 2.10 should be an analysis, not an introduction repeated

### Applies? **Yes.** `cap2.tex:448–468` (Section 2.10 "Summary and Research Gap") largely restates content from Chapter 1 rather than synthesising the literature just reviewed.

### Proposed changes:
Rewrite 2.10 as a **genuine synthesis** in three parts:

**Part 1 — Integrative summary (1 paragraph):**
Briefly integrate the main themes across 2.1–2.9: supply-chain attack taxonomies, dependency-graph risk, ecosystem studies for npm/PyPI, detection tools and platforms, LLM limitations, and distributed analysis challenges.

**Part 2 — Coverage matrix showing the research gap:**

| Paper | Vuln Scanning | Malicious Code | Typosquatting | Build Analysis | Secret Detection | Ecosystem Scale |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|
| Ohm et al. 2020 | | ✓ | ✓ | | | |
| Ladisa et al. 2023 | | ✓ | | ✓ | | |
| Zimmermann et al. 2019 | ✓ | | | | | ✓ (npm) |
| Vu et al. 2020 | | | ✓ | | | ✓ (PyPI) |
| Taylor et al. 2020 | | | ✓ | | | ✓ (npm) |
| Li et al. 2023 | ✓ | ✓ | | | | |
| **This thesis** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (Rust) |

**Part 2 — Quantified gap statement (use specific anchored claims, see also Item 14):**
> "Of the 30+ papers reviewed, 0 address Rust's `build.rs` mechanism, 0 combine all five detection dimensions, and 0 provide a distributed architecture for horizontal scaling at the scale of a full package registry."

**Part 3 — Thesis contributions as gap-filler (2–3 sentences):**
Map each gap directly to a thesis contribution and chapter. Then lead naturally into Chapter 3: "Given the gaps identified above, we propose…"

Existing subsections 2.10.1–2.10.3 should be tightened, with repetition of the Introduction removed and explicit cross-references added to key works (Backstabber, Zimmermann, Sonatype, SBOM/LLM papers).

### Rationale:
Section 2.10 currently duplicates Chapter 1; the supervisor explicitly expects synthesis. The coverage matrix is the most effective tool for showing that the combination of dimensions this thesis addresses is genuinely novel.

---

## Feedback Item 13: Section 2.9 — tech stack justification → move to methodology

### Applies? **Yes.** `cap2.tex:420–447` (Section 2.9 "Distributed Systems for Large-Scale Analysis") compares Redis vs. RabbitMQ vs. Kafka and justifies picking Redis. This is a **design decision**, not a literature review.

### Proposed changes:
**Remove the technology comparison from Chapter 2.** Redistribute the content as follows:

| Content | Move to |
|---------|---------|
| 2.9.1 "Challenges of Ecosystem-Scale Analysis" | Chapter 3.1 / 3.4 "Analysis Framework Design" — as conceptual motivation for chosen design |
| 2.9.2 "Work Queue Architectures" (Redis vs. RabbitMQ vs. Kafka) | Chapter 4.4 "Distributed Work Queue" — explicitly labelled as design rationale, not literature review |

**Replace Section 2.9 in Chapter 2** with a short literature-focused section "Distributed Analysis at Scale" reviewing:
- How Zimmermann et al. (2019) scaled npm analysis to 100K+ packages
- How PyPI's Linehaul processes 200K+ packages
- What distributed architectures prior academic work has used (e.g., map-reduce, work queues)
- Gap: no prior work has applied distributed architectures to Rust ecosystem analysis at full-registry scale

Then renumber 2.10 to 2.9 if the old section is removed, or retain the short replacement section as 2.9.

### Rationale:
Aligns with standard thesis structure: Chapter 2 = prior work; Chapters 3–4 = design decisions. The current placement gives the impression that the architecture was chosen based on a literature review — when it was actually a design rationale. Phrases like "as we will see later" should also be removed.

---

## Feedback Item 14: Section 2.10 identifies problems but formulation is too general

### Applies? **Yes.** `cap2.tex:450–468` uses vague, unanchored language.

### Proposed changes (in tandem with Item 12):
Replace every vague gap statement with a specific, citation-anchored claim:

| Remove | Replace with |
|--------|-------------|
| "No existing work combines..." | "The closest work, Vu et al. (2020), combines typosquatting detection with metadata analysis for PyPI, but does not include build script heuristics or LLM-based scoring." |
| "There is a lack of research on deployment at scale..." | "Li et al. (2023) and Zhang et al. (2024) evaluate LLMs on curated benchmarks of ~100–1,000 samples; no prior work has deployed LLM-based scoring at the scale of an entire package registry (150K+ packages)." |
| "Security tools are used in a reactive way, isolated..." | **Remove entirely** — speculative without evidence. |
| "There is a lack of comprehensive frameworks..." | "Prior work generally treats vulnerability scanning, secret detection, build-script security and typosquatting as separate problems, implemented in separate tools or studies. We were unable to find any system that integrates all of these dimensions into a single, distributed analysis pipeline for Rust." |
| Generic claims about Rust gaps | "Existing measurement studies focus on npm, PyPI and related ecosystems. There is currently no comparable empirical mapping for crates.io." |

Also add explicit cross-references in 2.10 back to the key papers reviewed (Backstabber, Zimmermann, Sonatype, SBOM/LLM), so the reader can see synthesis rather than repetition.

### Rationale:
Eliminates vague formulations. Makes claims falsifiable and properly sourced, which is what the supervisor expects from a research gap section.

---

## Feedback Item 15: Axios compromised supply chain attack (2 links)

### Applies? **Yes.** Both links describe a March 2026 supply chain attack on `axios` (npm, 100M+ weekly downloads), highly relevant to the threat landscape discussion.

### Research findings (from both articles):

**Attack summary (March 30–31, 2026):**
- `axios@1.14.1` and `axios@0.30.4` were compromised via a hijacked maintainer account (`jasonsaayman`)
- The attacker injected a phantom dependency `plain-crypto-js@4.2.1` into `package.json`; `plain-crypto-js` was never imported — its sole purpose was a `postinstall: "node setup.js"` hook
- `setup.js` was a cross-platform RAT dropper targeting macOS, Windows, and Linux
- The attacker pre-staged the malicious dependency **18 hours** before publishing the compromised axios versions
- The dropper contacted C2 at `sfrclak.com:8000`, downloaded platform-specific payloads, then **deleted itself** and replaced `package.json` with a clean stub to evade forensic detection
- Both versions were live for **~3 hours** before npm removed them
- Detection relied on **OIDC provenance mismatch**: legitimate releases used GitHub Actions OIDC; the malicious versions used a stolen classic token — directly demonstrating SLSA L2 value

### Location:
**Table 2.1** (Landmark Incidents) — add a new row. **Section 2.1.2** (Landmark Incidents) — add a paragraph after the xz-utils description.

### Suggested table row:
| Package | Year | Attack Vector | Impact |
|---------|------|--------------|--------|
| axios | 2026 | Account compromise + phantom dependency + postinstall hook | 100M+ weekly downloads; cross-platform RAT |

### Suggested paragraph:

> A very recent example is the compromise of the widely-used `axios` HTTP client library in March 2026. An attacker hijacked a maintainer's npm credentials and published malicious versions (`1.14.1` and `0.30.4`) that introduced a hidden phantom dependency, `plain-crypto-js`, whose `postinstall` hook dropped a cross-platform remote access trojan (RAT) on Windows, macOS and Linux. The attack pre-staged the malicious dependency 18 hours before publication, and both versions were live for approximately three hours before removal. Notably, detection relied on an OIDC provenance mismatch — legitimate releases used GitHub Actions OIDC signing, while the malicious versions used a stolen classic token — demonstrating the practical value of SLSA L2 controls. The technique of using lifecycle hooks to execute arbitrary code is directly analogous to the `build.rs` post-compile execution vector in Rust~\cite{oxsecurity2026axios,stepsecurity2026axios}.

### Bibliography entries:
```bibtex
@misc{oxsecurity2026axios,
  title = {{Axios Compromised With a Malicious Dependency}},
  author = {{OX Security}},
  year = {2026},
  url = {https://www.ox.security/blog/axios-compromised-with-a-malicious-dependency}
}
@misc{stepsecurity2026axios,
  title = {{axios Compromised on npm - Malicious Versions Drop Remote Access Trojan}},
  author = {{StepSecurity}},
  year = {2026},
  url = {https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan}
}
```

### Rationale:
Keeps the thesis current with 2026 attacks. The axios incident elegantly ties together multiple themes: account compromise, lifecycle hook abuse (analogous to `build.rs`), phantom dependencies, and SLSA L2 provenance detection — making it ideal for cross-referencing Items 2, 5, and 13.

---

## Additional Observations (not in original feedback but worth fixing)

### Missing bibliography entries
`myBib.bib` currently contains only ~6 unrelated entries (Knuth 1998, ECB 2025, Jackson 2001, NIST 2013, Takahashi 2013, one empty misc). **All ~30+ works cited in the thesis need adding.** The bib keys for all items in this document should be promoted from `thesis_draft.md` into `myBib.bib` as a priority.

### TODO markers
- `cap1.tex:13` — "TODO: Citation" for npm supply chain incidents
- `cap2.tex:11` — "TODO CITATION" for Ken Thompson's "Reflections on Trusting Trust"
- `cap2.tex:141` — "TODO: formula" for CVSS scoring formula

### Typos (representative sample — a full spell-check pass is needed)
| Location | Current | Correction |
|----------|---------|------------|
| Abstract | memofry | memory |
| Abstract | delievers | delivers |
| Abstract | heurisitc | heuristic |
| `cap1.tex:9` | thidparty | third-party |
| `cap2.tex:44` | unknownm | unknown |
| `cap2.tex:51` | THe | The |
| `cap2.tex:112` | sz-utils | xz-utils |
| `cap2.tex:376` | opperate | operate |
| Throughout | depdendencies | dependencies |
| Throughout | arhitecture | architecture |
| Throughout | wich | which |

### Inconsistent sectioning
Section 2.4 (Malicious Code Detection) uses a mix of `\subsection` for some subsections and prose-only for others (e.g., "Data exfiltration" at line 230 is bold text, not a labeled subsection). Standardize to either always use `\subsection` or always use `\textbf{}` within a prose narrative.

### LLM results tables in Chapter 7 are empty
`cap7.tex:458–477` shows an all-zeros LLM score distribution because the module was disabled. **Either remove these tables or re-run before final submission** — an empty table with "0" values looks like a methodological failure.

### CVSS formula missing
`cap2.tex:141` has `% TODO: formula`. The CVSS v3.1 base score formula should be inserted:
$$
\text{BaseScore} =
\begin{cases}
\text{Roundup}(\min(\text{Impact} + \text{Exploitability},\, 10)) & \text{if Scope = Unchanged} \\
\text{Roundup}(\min(1.08 \times (\text{Impact} + \text{Exploitability}),\, 10)) & \text{if Scope = Changed}
\end{cases}
$$

### Chapter 8 comparison section empty
`cap8.tex:17` has `TODO: After rerun of framework` — the "Comparison with Existing Approaches" section is entirely blank. This must be completed before submission.

---

## Summary of Impact

| Priority | Item | Reason |
|----------|------|--------|
| **Critical** | Item 11 (unverifiable 30% claim) | Academic integrity — must remove or replace with sourced claim |
| **High** | Item 12 (rewrite Section 2.10) | Currently duplicates Chapter 1; supervisor expects synthesis with coverage matrix |
| **High** | Item 13 (move Section 2.9) | Design justification in literature review is incorrect placement |
| **High** | Item 1 (subsection flattening) | Structural quality issue raised directly by supervisor |
| **High** | Missing bib entries | All citations must have corresponding `.bib` entries |
| **Medium** | Items 2, 3, 5 (SLSA, SBOM, Sigstore) | Major frameworks the supervisor explicitly asked about |
| **Medium** | Items 4, 6, 7 (Backstabber dataset, PyPI/Linehaul, Sonatype) | Empirical depth and cross-ecosystem grounding |
| **Medium** | Item 8 (Zimmermann scope clarification) | Avoids misleading inference that npm findings directly apply to Rust |
| **Medium** | Item 15 (axios 2026 attack) | Most recent high-profile incident; ties to build.rs analogy and SLSA |
| **Medium** | Items 9–10 (LLM/tool comparison tables) | Improves analytical depth; responds to supervisor's structured comparison request |
| **Medium** | Item 14 (specificity of gap statements) | In tandem with Item 12; makes gaps falsifiable |
| **Low** | Typos | Cosmetic but numerous; run a spell-check pass |
| **Low** | CVSS formula | "TODO" is unprofessional in final document |
| **Low** | Chapter 8 empty section | Must be completed but depends on framework re-run |

## Application checklist (suggested order)

1. Remove the 30% claim (Item 11) — immediate academic integrity fix
2. Add all missing `.bib` entries
3. Flatten subsections (Item 1) — structural prerequisite before adding new content
4. Add SLSA + Sigstore subsection in 2.1 (Items 2 & 5)
5. Add SBOM subsection in 2.2 (Item 3)
6. Expand Backstabber paragraph with dataset + reuse (Item 4)
7. Add Sonatype paragraph in 2.2.2 (Item 7)
8. Expand PyPI/Linehaul/YARA paragraph in 2.2.2 (Item 6)
9. Clarify and expand Zimmermann paragraph (Item 8)
10. Add axios incident to Table 2.1 and Section 2.1.2 (Item 15)
11. Replace LLM prose with comparative table in 2.6.2 (Item 9)
12. Replace cargo-tool prose with comparative table in 2.8.1 (Item 10)
13. Move Section 2.9 content to Chapters 3–4 and replace with lit-review text (Item 13)
14. Rewrite Section 2.10 with coverage matrix and specific gap statements (Items 12 & 14)
15. Fix typos, CVSS formula TODO, and empty Chapter 8 section



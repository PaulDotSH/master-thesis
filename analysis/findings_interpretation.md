## 6. Executable Files in Crates

Only **7,986 crates (3.5% of scanned)** ship executable binaries. However, among these, **5,409 (67.7%) have known vulns** — a far higher rate than the ecosystem average of 32.1%.

| Download bracket | Crates with executables | % |
|-----------------|------------------------|----|
| ≥1M downloads | 443 | 5.7% |
| 100K–1M | 894 | 8.4% |
| 10K–100K | 1,544 | 3.4% |
| 1K–10K | 2,291 | 1.9% |
| 100–1K | 1,602 | 4.2% |
| <100 | 1,212 | 3.5% |

**Key insight:** Crates with 100K–1M downloads have the highest rate of executable inclusion (8.4%). These are widely-used tools that execute on users' machines — making their high vulnerability rate (67.7%) particularly dangerous: users not only depend on these crates at build time but also *run* them, expanding the attack surface from supply chain to runtime.

---

## 7. Temporal Trends

### Crate Creation vs Vulnerability Rate

| Year | Crates created | % with vulns |
|------|---------------|--------------|
| 2014 | 598 | 16.1% |
| 2016 | 3,594 | 25.3% |
| 2018 | 7,706 | 24.4% |
| 2020 | 17,120 | 28.9% |
| 2022 | 25,529 | 23.6% |
| 2024 | 36,050 | 26.8% |
| 2026 | 51,809 | 31.1% |

**Key insight:** The ecosystem has grown exponentially (598 crates in 2014 → 51,809 in 2026), but the vulnerability rate has been relatively stable at 24–31%. The slight upward trend in 2025–2026 (29.2% → 31.1%) may reflect improved detection (more RustSec advisories published) rather than worsening code quality.

### Vulnerability Rate by Crate Age

| Age bracket | % vuln | Crates |
|------------|--------|--------|
| < 6 months | 30.9% | 60,917 |
| 6mo–1yr | 29.2% | 24,992 |
| 1–2 years | 27.4% | 38,951 |
| 2–5 years | 25.4% | 83,240 |
| 5+ years | 26.3% | 56,650 |

**Key insight:** Counter-intuitively, the *newest* crates (<6 months) have the *highest* vulnerability rate (30.9%). Possible explanations: (a) new crates often depend on the latest versions which have more published advisories, (b) inexperienced developers are more likely to introduce vulns, (c) newer crates haven't had time to patch known issues.

### Download Velocity vs Vulns

| Velocity bracket | % vuln | Avg vulns/crate |
|-----------------|--------|-----------------|
| High (≥1K/day) | 25.2% | 1.25 |
| Medium (100–1K/day) | 31.3% | 2.54 |
| Low (10–100/day) | 32.1% | 2.29 |
| Very low (<10/day) | 26.2% | 1.69 |

**Key insight:** The most popular (high-velocity) crates have the *lowest* vulnerability rate (25.2%) and fewest average vulns (1.25). This suggests that high-visibility crates receive more scrutiny and faster patching. The medium/low velocity crates (the "long tail") carry disproportionate risk — popular enough to have users, but not popular enough to attract security review.

---

## 8. LLM Malicious Score Analysis

The LLM-based malicious code detector produced **overwhelmingly neutral scores** (overall average: -0.13). Only **2 crates** scored ≥75 (considered "malicious"), and only **5 crates** scored above the "benign" threshold.

Additionally, **34,366 crates (13% of all crates)** have `llm_malicious_score = -1`, meaning they **failed analysis entirely** — the crate could not be downloaded, built, or scanned. This is the single largest category in the LLM score distribution (bucket 0 at -5, containing all -1 scores).

**Key insight:** The LLM detector has extremely low signal. Out of 226,546 successfully scanned crates, it flagged 2 as potentially malicious — both of which did have cargo-audit vulns. The detector's practical utility is limited: it catches almost nothing, and the tiny number of flags makes it hard to assess false positive rate. More concerningly, 34,366 crates couldn't be analyzed at all, representing a significant gap in LLM coverage.

---

## 9. Typosquatting Detection

**38,495 name-similarity pairs** were detected across the ecosystem. Of these:
- 14,447 had high combined similarity scores
- 891 had very high similarity scores (≥95)
- Max combined score: 98

Examples of high-risk pairs:
- `opentelemetry-appender` vs `opentelemetry-appender` (score 98) — single character difference
- `clap-verbosity-flag2` vs `clap-verbosity-flag` (score 97) — suffix variation
- `proc-macro-error-attr2` vs `proc-macro-error-attr` (score 97) — 91M downloads for the original

**Key insight:** Several typosquat-like pairs have *millions* of downloads for the legitimate crate and only thousands for the potential squatter — a classic asymmetry suggesting impersonation. The `azure_storage_blob` vs `azure_storage_blobs` pair (score 97) is particularly concerning: the legitimate crate has 16.7M downloads while the similar-named one has 1.1M.

---

## 10. Compound Risk Indicators

### Crates with Both Secrets AND Vulns (Part D of SQL 04)

The intersection of leaked secrets + known vulns represents heightened risk: a crate that both exposes credentials AND has exploitable code paths. Notable examples:
- `beacon-metrics-gazer`: 20,487 secrets + 11 vulns
- `mpl-trifle`: 5,541 secrets + 19 vulns
- `safe-token` & related Solana Program Library crates: 1,079 secrets each + 32 vulns
- `solarti-*` crates (Solarti = Solana fork): 961 secrets each + 17 vulns

### Crates with Suspicious build.rs + Executables + Vulns (Part E of SQL 10)

The nexo-* ecosystem (30 crates) exhibits all three red flags: process-spawning build scripts, executable binaries, AND 270 vulns + 270 secrets each. This is a textbook high-risk profile warranting manual investigation.

---

## 11. Analysis Performance

| Metric | Value |
|--------|-------|
| Median analysis time | 1.46 seconds |
| Mean analysis time | 15.1 seconds |
| p95 analysis time | 86.8 seconds |
| Max analysis time | 52.1 minutes |
| Dominant component | Cargo-audit (avg 11.2s) |

**Key insight:** The analysis pipeline is dominated by `cargo-audit` (74% of mean time). Gitleaks is second at 3.1s avg. Download time is relatively minor at 1.5s avg. The p95 of 87 seconds and max of 52 minutes indicate some crates have extremely large dependency trees or complex build systems that cause pathological analysis times.

---

## Summary of Key Findings

1. **32.1% of scanned crates have known vulns** (72,773 / 226,546). 82.6% of findings are informational. Only ~11% are High/Critical.
2. **34,366 crates (13%) failed analysis entirely** — a substantial blind spot in the dataset.
3. **95.8% of leaked secrets are generic-api-key matches** — likely high false-positive rate, but 561 crates leaking GitHub PATs is genuinely concerning.
4. **The Substrate/Polkadot ecosystem is the single largest source of transitive vulnerability risk** due to a few widely-depended-upon crates with many vulns.
5. **Crates shipping executables have a 67.7% vulnerability rate** — more than double the ecosystem average.
6. **Popular crates are safer**: high-download-velocity crates have lower vuln rates (25.2%) than medium-popularity crates (32.1%).
7. **Newest crates are most vulnerable** (30.9% rate for <6 months old) — likely due to unpatched dependencies and less review.
8. **The LLM malicious code detector has near-zero practical signal** (2 flags out of 226,546 scanned crates) and failed on 34,366 crates.
9. **Typosquatting is a real threat**: 891 very-high-similarity pairs detected, some with massive download asymmetry suggesting impersonation.
10. **The top 100 most-vulnerable crates likely contain a large fraction of all ecosystem vulnerabilities** — concentrated risk that targeted remediation could address.
11. **Build script risk is concentrated**: only 1.41% of scanned crates spawn processes in build.rs, but this is the most powerful supply chain attack vector.

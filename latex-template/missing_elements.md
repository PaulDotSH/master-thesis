# Missing Thesis Elements

This document contains thesis elements that should be integrated into appropriate chapters.

---

## 1. Research Questions (Chapter 1 - Introduction)

The thesis should clearly state specific, answerable research questions. Based on your work:

### Primary Research Question

**RQ0**: How can we design and implement a comprehensive, distributed framework for automated security analysis of the Rust crates.io ecosystem that integrates multiple complementary detection techniques?

### Secondary Research Questions

**RQ1 (Prevalence)**: What is the current security posture of the crates.io ecosystem in terms of known vulnerabilities, hardcoded secrets, and suspicious build script behaviors?

**RQ2 (Detection Effectiveness)**: How effective is LLM-based analysis for detecting potentially malicious code patterns in Rust crates compared to static heuristic approaches?

**RQ3 (Typosquatting)**: What is the prevalence of typosquatting attempts in crates.io, and how effectively can string similarity algorithms detect them when tuned for Rust naming conventions?

**RQ4 (Risk Propagation)**: How does security risk propagate through the crates.io dependency graph, and what proportion of the ecosystem is transitively affected by identified security issues?

**RQ5 (Scalability)**: Can ecosystem-scale security analysis be performed efficiently using distributed processing with dependency-aware scheduling?

---

## 2. Comprehensive Threat Model (Chapter 2 or Chapter 3)

### 2.1 System Model

The crates.io ecosystem consists of the following entities:
- **Crate authors/maintainers**: Individuals who publish and maintain crates
- **Crate consumers**: Developers who depend on crates in their projects
- **crates.io registry**: The central package repository
- **Build infrastructure**: Cargo, rustc, and CI/CD systems that compile crates
- **End users**: Users of software built with Rust crates

### 2.2 Attacker Model

We consider the following attacker capabilities and limitations:

**Attacker Capabilities**:
- Can register arbitrary crate names (subject to registry policies)
- Can publish crate versions containing arbitrary Rust code
- Can execute code during build time via `build.rs` scripts
- Can gain maintainer access through social engineering or credential compromise
- Has knowledge of popular crates and naming conventions
- Can observe download statistics and ecosystem trends

**Attacker Limitations**:
- Cannot directly modify crates owned by others (without account compromise)
- Cannot modify crates.io infrastructure
- Cannot bypass cryptographic signature verification (if implemented)
- Limited resources for sustained attacks (assumption varies by attacker class)

### 2.3 Attacker Classes

| Class | Motivation | Resources | Sophistication | Examples |
|-------|------------|-----------|----------------|----------|
| Script Kiddie | Experimentation, notoriety | Low | Low | Copy-paste malware |
| Cybercriminal | Financial gain | Medium | Medium | Cryptominers, credential stealers |
| Advanced Criminal | Financial gain at scale | High | High | Targeted supply chain attacks |
| Nation-State | Espionage, sabotage | Very High | Very High | Long-term infiltration (xz-utils style) |

### 2.4 Attack Vectors Addressed by This Framework

| Attack Vector | Detection Module | Detection Method |
|---------------|------------------|------------------|
| Known vulnerabilities | cargo audit | RustSec database matching |
| Hardcoded secrets | Gitleaks | Regex + entropy analysis |
| Malicious build.rs | Build script heuristics | Pattern matching for suspicious APIs |
| Typosquatting | Typosquat scorer | Multi-algorithm string similarity |
| Obfuscated malware | LLM analysis | Semantic code understanding |
| Transitive risk | Dependency analysis | Graph propagation |

### 2.5 Assumptions

1. **Crate source availability**: Published crates have source code available for analysis.
2. **Static analysis sufficiency**: Many malicious behaviors can be detected through static analysis without execution.
3. **LLM reliability**: LLM-based analysis provides useful signals despite potential hallucinations.
4. **Known attack patterns**: Attackers use identifiable patterns that can be detected through heuristics.
5. **Dependency graph accuracy**: Cargo.toml accurately represents crate dependencies.

### 2.6 Out of Scope

- Runtime behavioral analysis (dynamic analysis)
- Binary analysis of compiled crates
- Network traffic analysis during crate usage
- Authentication/authorization attacks on crates.io itself
- Social engineering detection
- Detection of zero-day vulnerability exploitation

---

## 3. Evaluation Methodology (Chapter 4 or 5)

### 3.1 Datasets

**Primary Dataset**: Full crates.io ecosystem
- Total crates: ~150,000+
- Total versions: Millions
- Coverage: All publicly available crates as of [DATE]
- Source: Official crates.io database dump + git repositories

**Ground Truth Dataset** (for validation):
- Known malicious crates from incident reports (CrateDepression, faster_log, async_println, etc.)
- Known typosquatting attempts (documented removals)
- RustSec advisory database entries

### 3.2 Metrics

**For Vulnerability Detection (cargo audit)**:
- Number of crates with known vulnerabilities
- Severity distribution (CVSS scores)
- Transitive vulnerability exposure

**For Secret Detection (Gitleaks)**:
- True Positive Rate (validated secrets)
- False Positive Rate (estimated through sampling)
- Secret type distribution

**For Build Script Analysis**:
- Prevalence of suspicious patterns
- Distribution by heuristic type
- Correlation with other risk indicators

**For Typosquatting Detection**:
- Precision: Of flagged pairs, how many are true typosquats?
- Recall: Of known typosquats, how many were detected?
- Score distribution and threshold analysis

**For LLM Analysis**:
- Score distribution across ecosystem
- Correlation with known malicious crates
- Analysis of high-scoring crates (manual review)

**For System Performance**:
- Throughput: Crates analyzed per hour
- Resource utilization: CPU, memory, disk, network
- Scalability: Performance with increasing worker count

### 3.3 Baselines

| Analysis Type | Baseline Comparison |
|---------------|---------------------|
| Vulnerability detection | Standard cargo audit without ecosystem context |
| Secret detection | Gitleaks with default rules only |
| Build script analysis | No existing comparable tool (novel contribution) |
| Typosquatting | typomania (Rust Foundation tool) |
| LLM analysis | No existing comparable tool at ecosystem scale |

### 3.4 Validation Approach

1. **Known Malicious Crates**: Verify detection of documented attacks
2. **Manual Sampling**: Random sample review of flagged crates (n=100-200)
3. **False Positive Analysis**: Sample review of clean crates flagged as suspicious
4. **Cross-Validation**: Compare findings across different detection modules

---

## 4. Limitations (Chapter 5 or 6)

### 4.1 Detection Limitations

**False Negatives (Missed Threats)**:
- Novel attack patterns not matching existing heuristics
- Sophisticated obfuscation techniques
- Time-delayed or condition-triggered malware
- Attackes targeting runtime rather than build time
- Social engineering and account compromise (not code-level)

**False Positives (Misidentified Threats)**:
- Legitimate crates with unusual but non-malicious patterns
- Test code containing security-related patterns
- Security tools that legitimately use suspicious APIs
- High entropy in legitimately compressed/encoded data
- Common names triggering typosquatting false alarms

### 4.2 LLM-Specific Limitations

- **Hallucinations**: LLM may report non-existent vulnerabilities
- **Context window**: Large codebases require chunking, potentially missing cross-file patterns
- **Reproducibility**: Non-deterministic outputs even with temperature=0
- **Model limitations**: Local model (Qwen2.5-Coder-14B) less capable than larger models
- **Adversarial robustness**: Attackers may craft code to evade LLM detection

### 4.3 Scalability Limitations

- Analysis time grows with codebase size
- LLM analysis is compute-intensive
- Full ecosystem analysis requires significant infrastructure
- Dependency ordering can create bottlenecks for heavily-depended crates

### 4.4 Ground Truth Limitations

- Limited confirmed malicious crate samples
- Unknown false negative rate (undetected attacks)
- Difficulty distinguishing abandoned vs. malicious crates
- Temporal factors (some attacks may have been cleaned up)

### 4.5 Generalizability Limitations

- Framework designed specifically for Rust/crates.io
- Build script analysis assumes Rust-specific build.rs patterns
- Typosquatting heuristics tuned for Rust naming conventions
- May require adaptation for other ecosystems

---

## 5. Ethical Considerations (Chapter 1 or Chapter 6)

### 5.1 Responsible Disclosure

When potentially malicious crates are identified:
1. Results are not published with specific crate names until reported
2. Findings are reported to the Rust Security Response WG
3. Crate authors are notified if contact information is available
4. A responsible disclosure timeline (90 days) is followed before public discussion

### 5.2 Data Handling

- All analyzed data is publicly available from crates.io
- No private or proprietary code is included in the analysis
- Results database does not contain actual secret values (only detection metadata)
- Crate download statistics are used only for prioritization, not surveillance

### 5.3 Dual-Use Concerns

This research could theoretically aid attackers by:
- Revealing detection blind spots
- Identifying prevalent patterns to avoid
- Providing a framework that could be repurposed for malicious targeting

**Mitigations**:
- Focus on defensive capabilities, not offensive techniques
- Detection rules are descriptive, not prescriptive for evasion
- Open-sourcing enables community review and improvement
- Coordination with Rust Foundation security team

### 5.4 Impact on Crate Authors

- False positives may unfairly stigmatize legitimate crates
- Public flagging could damage maintainer reputation
- Unmaintained crate warnings may not reflect actual risk

**Mitigations**:
- Results are presented with confidence levels
- Appeal/review process for disputed findings
- Context provided for all flags (not binary "malicious/safe")

### 5.5 Research Ethics Compliance

- No human subjects involved
- All data is publicly published open-source code
- No interaction with or deception of crate authors
- Research registered with [INSTITUTION] ethics committee (if required)

---

## 6. Artifact Documentation (Appendix or Separate Document)

### 6.1 Software Artifacts

| Artifact | Description | Location |
|----------|-------------|----------|
| crates_downloader | Main analysis framework (Rust) | `crates_downloader/` |
| webpanel | Dashboard for results visualization | `webpanel/` |
| Database schema | PostgreSQL schema for results | `migrations/` |
| Docker configuration | Deployment configuration | `docker-compose.*.yml` |
| Configuration | Analysis parameters | `config.toml` |

### 6.2 Data Artifacts

| Artifact | Description | Format |
|----------|-------------|--------|
| Analysis results | Full ecosystem scan results | PostgreSQL dump |
| Vulnerability data | cargo audit findings | JSON/PostgreSQL |
| Secret detections | Gitleaks findings | JSON/PostgreSQL |
| Build script analysis | Heuristic flags | PostgreSQL |
| Typosquatting scores | Similarity computations | PostgreSQL |
| LLM analysis | Maliciousness scores and notes | PostgreSQL |

### 6.3 Reproducibility Requirements

**Hardware Requirements**:
- CPU: 8+ cores recommended for parallel analysis
- RAM: 32GB+ for LLM analysis
- Storage: 500GB+ for crate downloads (or tmpfs/ramdisk)
- GPU: Optional, for faster LLM inference

**Software Requirements**:
- Rust 1.75+ (stable)
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose
- Gitleaks 8+
- LM Studio (or compatible OpenAI API server)

**Reproduction Steps**:
1. Clone repository
2. Configure `config.toml` with database and Redis URLs
3. Initialize database with migrations
4. Download crates.io database dump
5. Run workers: `cargo run --release`
6. View results via webpanel

### 6.4 Evaluation Checklist (Artifact Evaluation Standard)

- [ ] Documentation sufficient for setup
- [ ] Dependencies clearly listed
- [ ] Configuration documented
- [ ] Sample data or instructions for data acquisition
- [ ] Expected outputs documented
- [ ] License specified (MIT/Apache 2.0)
- [ ] Test suite available
- [ ] Performance benchmarks reproducible

---

## 7. Bibliography Notes

### Missing Citations (marked TODO in cap2.tex)

The following citations need to be added:

```bibtex
@inproceedings{thompson1984trusting,
  title={Reflections on trusting trust},
  author={Thompson, Ken},
  booktitle={ACM Turing Award Lectures},
  year={1984}
}

@article{ohm2020backstabber,
  title={Backstabber's knife collection: A review of open source software supply chain attacks},
  author={Ohm, Marc and Plate, Henrik and Sykosch, Arnold and Meier, Michael},
  journal={International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment},
  year={2020}
}

@inproceedings{ladisa2023taxonomy,
  title={A taxonomy of attacks on open-source software supply chains},
  author={Ladisa, Piergiorgio and others},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2023}
}

@inproceedings{zimmermann2019small,
  title={Small world with high risks: A study of security threats in the npm ecosystem},
  author={Zimmermann, Markus and Staicu, Cristian-Alexandru and Tenny, Cam and Pradel, Michael},
  booktitle={USENIX Security Symposium},
  year={2019}
}

@inproceedings{taylor2020typosquatting,
  title={A large-scale study of typosquatting abuses in npm},
  author={Taylor, Matthew and others},
  booktitle={Mining Software Repositories (MSR)},
  year={2020}
}

@inproceedings{vu2020typosquatting,
  title={Typosquatting and combosquatting attacks on the python ecosystem},
  author={Vu, Due Ly and others},
  booktitle={IEEE European Symposium on Security and Privacy Workshops},
  year={2020}
}

@online{sentinelone2022cratedepression,
  title={CrateDepression: Rust Supply-Chain Attack Infects Cloud CI Pipelines with Go Malware},
  author={SentinelOne Labs},
  year={2022},
  url={https://www.sentinelone.com/labs/cratedepression-rust-supply-chain-attack-infects-cloud-ci-pipelines-with-go-malware/}
}

@online{hackernews2025rustmalware,
  title={Malicious Rust Crates Steal Solana and Ethereum Keys},
  author={The Hacker News},
  year={2025},
  url={https://thehackernews.com/2025/09/malicious-rust-crates-steal-solana-and.html}
}
```

---

## 8. Integration Suggestions

| Element | Suggested Location |
|---------|-------------------|
| Research Questions | Chapter 1.3 (after problem statement) |
| Threat Model | Chapter 2.1.5 (new subsection) or Chapter 3.1 |
| Evaluation Methodology | Chapter 4.1 (Experimental Setup) |
| Limitations | Chapter 5.5 (after results discussion) |
| Ethical Considerations | Chapter 1.4 or Chapter 6.2 |
| Artifact Documentation | Appendix A |
| Bibliography | references.bib |

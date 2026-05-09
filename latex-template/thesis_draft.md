# Thesis Draft: Comprehensive Security Analysis Framework for the Rust Crates.io Ecosystem

## Chapter 8: Discussion

#### 8.3.4 Ground Truth Limitations

- **Limited confirmed malicious samples**: Only a small number of Rust crates have been publicly documented as malicious, limiting validation.
- **Unknown false negative rate**: We cannot determine how many actual attacks exist but were not detected.
- **Temporal limitations**: Some malicious crates may have been removed from crates.io before analysis.
- **Labeling ambiguity**: The boundary between "suspicious" and "malicious" is subjective and context-dependent.

#### 8.3.5 Generalizability Limitations

- The framework is designed specifically for Rust and crates.io; significant adaptation would be required for other ecosystems.
- Build script analysis assumes Rust-specific `build.rs` patterns; equivalent patterns in Python (`setup.py`) or JavaScript (`postinstall`) would require different heuristics.
- Typosquatting detection is tuned for Rust naming conventions (hyphen/underscore usage, `-rs` suffix).

### 8.4 Threats to Validity

- **Internal validity**: The correctness of the CVSS implementation and string similarity algorithms has been verified through unit tests, but edge cases may exist.
- **External validity**: Results are limited to crates available on crates.io with valid Git repository links. Private or enterprise crate registries are not covered.
- **Construct validity**: The LLM malicious score is a heuristic measure and does not guarantee the presence or absence of malicious behavior.

---

## Bibliography

*(To be populated with full references. Key references for the thesis include:)*

- Ohm, M., Plate, H., Sykosch, A., & Meier, M. (2020). Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks. *DIMVA 2020*.
- Ladisa, P., Plate, H., Martinez, M., & Barais, O. (2023). A Taxonomy of Attacks on Open-Source Software Supply Chains. *IEEE S&P 2023*.
- Zimmermann, M., Staicu, C. A., Tenny, C., & Pradel, M. (2019). Small World with High Risks: A Study of Security Threats in the npm Ecosystem. *USENIX Security 2019*.
- Taylor, M., Patel, R., & Shakeri, S. (2020). A Large-Scale Study of Typosquatting in npm. *MSR 2020*.
- Vu, D. L., Pashchenko, I., Massacci, F., Plate, H., & Sabetta, A. (2020). Typosquatting and Combosquatting Attacks on the Python Ecosystem. *IEEE EuroS&P Workshops 2020*.
- Garrett, K., Ferreira, G., Jia, L., Zhu, J., & Le Goues, C. (2019). Detecting Suspicious Package Updates. *ICSE NIER 2019*.
- Li, H., Hao, Y., Zhai, Y., & Qian, Z. (2023). Assessing the Promise and Pitfalls of ChatGPT for Automated Vulnerability Detection. *arXiv preprint*.
- Thompson, K. (1984). Reflections on Trusting Trust. *Communications of the ACM*, 27(8), 761–763.
- NIST. (2019). *NIST SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations*.
- The Rust Secure Code Working Group. (2024). *RustSec Advisory Database*. https://rustsec.org/
- The crates.io Team. (2026). *crates.io Database Dump*. https://crates.io/data-access
- First CVSS v3.1 Specification Document, FIRST.org, 2019. https://www.first.org/cvss/v3.1/specification-document

---



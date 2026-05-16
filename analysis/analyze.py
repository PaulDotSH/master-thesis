#!/usr/bin/env python3
"""
Master Thesis - Rust Crate Ecosystem Security Analysis
======================================================
Runs SQL queries against the crates PostgreSQL database and generates
visualizations (PNG) + text data output for dissertation.

Usage:
    python3 analyze.py [--db DB_URL] [--out-dir OUTPUT_DIR] [--skip-plots]
"""

import argparse
import csv
import io
import math
import os
import subprocess
import sys

# --- Configuration -----------------------------------------------------------
DEFAULT_DB = os.environ.get("PGDATABASE", "postgres://postgres:postgres@localhost:5432/crates")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
PLOTS_DIR = os.path.join(OUTPUT_DIR, "plots")
DATA_DIR = os.path.join(OUTPUT_DIR, "data")

# --- Matplotlib setup --------------------------------------------------------
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "font.size": 9,
    "axes.titlesize": 11,
    "axes.labelsize": 9,
    "figure.figsize": (10, 5.5),
})


# =============================================================================
# UTILITIES
# =============================================================================

def run_query(sql_path, db_url=DEFAULT_DB):
    """Run a SQL file via psql, executing each statement separately.
    Returns a list of dicts from all result sets merged."""
    with open(sql_path, "r") as f:
        sql_text = f.read()

    # Split into individual statements, skipping empty ones and comments-only blocks
    statements = []
    for stmt in sql_text.split(";"):
        stmt = stmt.strip()
        if not stmt:
            continue
        lines = [l for l in stmt.split("\n") if l.strip() and not l.strip().startswith("--")]
        if not lines:
            continue
        statements.append(stmt)

    all_rows = []
    for stmt in statements:
        cmd = [
            "psql", db_url,
            "--csv",
            "-c", stmt
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[WARN] psql error in {os.path.basename(sql_path)}: {result.stderr[:200]}", file=sys.stderr)
            continue
        chunk = result.stdout.strip()
        if not chunk:
            continue
        try:
            reader = csv.DictReader(io.StringIO(chunk))
            chunk_rows = [{k: v for k, v in r.items() if k is not None} for r in reader]
            all_rows.extend(chunk_rows)
        except Exception:
            pass
    return all_rows


def run_raw_query(query_text, db_url=DEFAULT_DB):
    """Run raw SQL text via psql and return list of dicts."""
    cmd = ["psql", db_url, "--csv", "-c", query_text]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] psql failed:\n{result.stderr}", file=sys.stderr)
        return []
    chunk = result.stdout.strip()
    if not chunk:
        return []
    reader = csv.DictReader(io.StringIO(chunk))
    return [{k: v for k, v in r.items() if k is not None} for r in reader]


def print_data_table(title, rows, keys=None):
    """Print data as a formatted table to stdout. Groups rows by key schema."""
    if not rows:
        print(f"\n--- {title} ---\n(no data)")
        return

    # Group rows by their dict keys (different result sets have different column sets)
    groups = {}
    group_order = []
    for row in rows:
        key_sig = tuple(sorted(k for k in row.keys() if k))
        if key_sig not in groups:
            groups[key_sig] = []
            group_order.append(key_sig)
        groups[key_sig].append(row)

    for gi, key_sig in enumerate(group_order):
        group_rows = groups[key_sig]
        group_keys = list(key_sig)
        if len(group_order) > 1:
            print(f"\n{'='*80}")
            print(f"  {title}  [Part {gi + 1}/{len(group_order)}]")
        else:
            print(f"\n{'='*80}")
            print(f"  {title}")
        print(f"{'='*80}")
        header = "  ".join(f"{str(k)[:18]:>18}" for k in group_keys)
        sep = "  ".join("-" * 18 for _ in group_keys)
        print(header)
        print(sep)
        for row in group_rows:
            vals = []
            for k in group_keys:
                v = row.get(str(k), "")
                if v is None:
                    v = ""
                v = str(v)[:22]
                vals.append(f"{v:>18}")
            print("  ".join(vals))
    print(f"{'='*80}\n")


def safe_float(val, default=0.0):
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def safe_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


# =============================================================================
# PLOT 1: Most Vulnerable Crates (Bar Chart)
# =============================================================================

def plot_most_vulnerable_crates(rows, out_dir):
    if len(rows) < 3:
        print("[SKIP] Not enough data for most-vulnerable crates plot")
        return
    rows = sorted(rows, key=lambda r: safe_float(r.get("risk_score", 0)), reverse=True)[:20]
    names = [r.get("crate_name", "?")[:30] for r in rows]
    risk = [safe_float(r.get("risk_score", 0)) for r in rows]
    vuln = [safe_int(r.get("vuln_count", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(range(len(names)), risk, color="#e74c3c", edgecolor="#c0392b", height=0.6)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("Risk Score (vuln_count × avg_severity + max_severity/10)")
    ax.set_title("Top 20 Most Vulnerable Crates")
    for i, (r, v) in enumerate(zip(risk, vuln)):
        ax.text(r + max(risk)*0.01, i, f"{r:.1f} ({v} vulns)", va="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "01_most_vulnerable_crates.png"))
    plt.close(fig)
    print(f"[PLOT] 01_most_vulnerable_crates.png")


# =============================================================================
# PLOT 2: Vuln-per-Download Ratio (Scatter)
# =============================================================================

def plot_vuln_per_download(rows, out_dir):
    if not rows:
        return
    dls = np.array([max(safe_int(r.get("crate_downloads", 0)), 1) for r in rows])
    vulns = np.array([safe_int(r.get("vuln_count", 0)) for r in rows])
    ratios = np.array([safe_float(r.get("vuln_per_log_download_ratio", 0)) for r in rows])

    fig = plt.figure(figsize=(12, 10))
    gs = fig.add_gridspec(3, 3, hspace=0.35, wspace=0.35,
                          width_ratios=[5, 1, 0.3], height_ratios=[1, 5, 1])

    ax_main = fig.add_subplot(gs[1, 0])
    ax_top = fig.add_subplot(gs[0, 0], sharex=ax_main)
    ax_right = fig.add_subplot(gs[1, 1], sharey=ax_main)
    ax_cbar = fig.add_subplot(gs[1, 2])

    hb = ax_main.hexbin(np.log10(dls), vulns, gridsize=40, cmap="YlOrRd",
                         mincnt=1, edgecolors="none")
    ax_main.set_xlabel("Crate Downloads (log10 scale)")
    ax_main.set_ylabel("Vulnerability Count")
    ax_main.set_title("Vulnerability Density: Vulns vs Popularity")

    cbar = fig.colorbar(hb, cax=ax_cbar, label="Crates per bin")
    cbar.ax.yaxis.set_label_position("left")

    ax_top.hist(np.log10(dls), bins=50, color="#e74c3c", alpha=0.7, edgecolor="#c0392b")
    ax_top.set_ylabel("Cr.\nCount", fontsize=7)
    ax_top.tick_params(labelsize=6)

    ax_right.hist(vulns, bins=40, orientation="horizontal", color="#3498db",
                  alpha=0.7, edgecolor="#2980b9")
    ax_right.set_xlabel("Cr.\nCount", fontsize=7)
    ax_right.tick_params(labelsize=6)

    plt.setp(ax_top.get_xticklabels(), visible=False)
    plt.setp(ax_right.get_yticklabels(), visible=False)

    ax_stats = fig.add_subplot(gs[2, 0])
    ax_stats.axis("off")
    stats_text = (
        f"Crates with vulns: {len(dls)}\n"
        f"Median downloads: {np.median(dls):,.0f}\n"
        f"Median vulns/crate: {np.median(vulns):.0f}\n"
        f"Mean vulns/crate: {np.mean(vulns):.1f}\n"
        f"Max vulns: {np.max(vulns):.0f}\n"
        f"Mean vuln/log-dl ratio: {np.mean(ratios):.1f}"
    )
    ax_stats.text(0.05, 0.95, stats_text, transform=ax_stats.transAxes,
                  fontsize=7, verticalalignment="top", fontfamily="monospace")

    fig.savefig(os.path.join(out_dir, "02_vuln_per_download_ratio.png"))
    plt.close(fig)
    print(f"[PLOT] 02_vuln_per_download_ratio.png")


# =============================================================================
# PLOT 3: Typosquatting Score Distribution (Histogram)
# =============================================================================

def plot_typosquat_distribution(bucket_rows, out_dir):
    if not bucket_rows:
        return
    lowers = [safe_float(r.get("bucket_lower_bound", 0)) for r in bucket_rows]
    counts = [safe_int(r.get("pair_count", 0)) for r in bucket_rows]
    labels = [f"{int(l)}-{int(l)+5}" for l in lowers]

    fig, ax = plt.subplots(figsize=(11, 5))
    bars = ax.bar(range(len(lowers)), counts, color="#8e44ad", edgecolor="#6c3483")
    ax.set_xticks(range(len(lowers)))
    ax.set_xticklabels(labels, rotation=45, fontsize=7)
    ax.set_xlabel("Combined Similarity Score Range")
    ax.set_ylabel("Number of Crate Pairs")
    ax.set_title("Typosquatting Detection: Distribution of Name Similarity Scores")
    for i, c in enumerate(counts):
        if c > 0:
            ax.text(i, c + max(counts)*0.02, str(c), ha="center", fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "03_typosquat_score_distribution.png"))
    plt.close(fig)
    print(f"[PLOT] 03_typosquat_score_distribution.png")


# =============================================================================
# PLOT 4: Secret Types Distribution (Bar)
# =============================================================================

def plot_secret_types(rows, out_dir):
    if len(rows) < 2:
        return
    rows = sorted(rows, key=lambda r: safe_int(r.get("occurrence_count", 0)), reverse=True)
    types = [r.get("secret_type", "?")[:35] for r in rows]
    counts = [safe_int(r.get("occurrence_count", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(12, max(6, len(types) * 0.22)))
    colors = plt.cm.Reds([0.3 + 0.7 * (i / max(len(types) - 1, 1)) for i in range(len(types))])
    bars = ax.barh(range(len(types)), counts, color=colors, edgecolor="#922b21", height=0.6)
    ax.set_yticks(range(len(types)))
    ax.set_yticklabels(types, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("Number of Findings")
    ax.set_title("Secrets Leaked: All Gitleaks Rule Matches (non-test/non-example locations)")
    for i, c in enumerate(counts):
        ax.text(c + max(counts)*0.01, i, str(c), va="center", fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "04_secret_types.png"))
    plt.close(fig)
    print(f"[PLOT] 04_secret_types.png")


# =============================================================================
# PLOT 5: Build.rs Suspicious Flags Overview (Horizontal Bar)
# =============================================================================

def plot_build_rs_flags(rows, out_dir):
    if not rows:
        return
    patterns = [r.get("pattern", "?") for r in rows]
    counts = [safe_int(r.get("crate_count", 0)) for r in rows]
    pcts = [safe_float(r.get("pct_of_scanned", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(10, 4))
    colors = ["#e74c3c", "#e67e22", "#f1c40f", "#2ecc71", "#3498db"]
    bars = ax.barh(range(len(patterns)), counts, color=colors[:len(patterns)], edgecolor="#2c3e50", height=0.5)
    ax.set_yticks(range(len(patterns)))
    ax.set_yticklabels(patterns, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Number of Crates")
    ax.set_title("Prevalence of Suspicious build.rs Patterns")
    for i, (c, p) in enumerate(zip(counts, pcts)):
        ax.text(c + max(counts)*0.01, i, f"{c} ({p}%)", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "05_build_rs_suspicious_flags.png"))
    plt.close(fig)
    print(f"[PLOT] 05_build_rs_suspicious_flags.png")


# =============================================================================
# PLOT 6: LLM Score vs Cargo-Audit Agreement (Grouped Bar)
# =============================================================================

def plot_llm_agreement(rows, out_dir):
    if not rows:
        return
    categories = sorted(set(r.get("llm_category", "") for r in rows))
    vuln_statuses = sorted(set(r.get("vuln_status", "") for r in rows))
    data = {}
    for r in rows:
        cat = r.get("llm_category", "")
        vs = r.get("vuln_status", "")
        data[(cat, vs)] = safe_int(r.get("crate_count", 0))

    fig, ax = plt.subplots(figsize=(11, 5))
    x = np.arange(len(categories))
    width = 0.35
    for i, vs in enumerate(vuln_statuses):
        vals = [data.get((cat, vs), 0) for cat in categories]
        bars = ax.bar(x + i * width, vals, width, label=vs, edgecolor="#2c3e50")
    ax.set_xticks(x + width / 2)
    ax.set_xticklabels([c.replace("LLM: ", "") for c in categories], fontsize=7, rotation=15)
    ax.set_ylabel("Number of Crates")
    ax.set_title("LLM Score vs Cargo-Audit Agreement Matrix")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "06_llm_vs_cargo_audit.png"))
    plt.close(fig)
    print(f"[PLOT] 06_llm_vs_cargo_audit.png")


# =============================================================================
# PLOT 7: Vulnerability Severity Distribution (Pie/Donut)
# =============================================================================

def plot_severity_distribution(rows, out_dir):
    if not rows:
        return
    labels = [r.get("severity_level", "?") for r in rows]
    counts = [safe_int(r.get("finding_count", 0)) for r in rows]
    colors = ["#922b21", "#e74c3c", "#f39c12", "#27ae60", "#7f8c8d"]

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        counts, labels=None, autopct="%1.1f%%", startangle=140,
        colors=colors[:len(labels)], pctdistance=0.75,
        wedgeprops={"edgecolor": "white", "linewidth": 1}
    )
    ax.legend(wedges, [f"{l} ({c})" for l, c in zip(labels, counts)],
              title="Severity Level", loc="center left", bbox_to_anchor=(1, 0.5), fontsize=7)
    ax.set_title("Cargo-Audit Findings by Severity Level")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "07_severity_distribution.png"))
    plt.close(fig)
    print(f"[PLOT] 07_severity_distribution.png")


# =============================================================================
# PLOT 8: Dependency Network - Most Depended-Upon (Bar)
# =============================================================================

def plot_dependency_centrality(rows, out_dir):
    if len(rows) < 2:
        return
    rows = sorted(rows, key=lambda r: safe_int(r.get("dependents_count", 0)), reverse=True)[:20]
    names = [r.get("dependency_name", "?")[:25] for r in rows]
    dep_counts = [safe_int(r.get("dependents_count", 0)) for r in rows]
    has_vuln = [r.get("has_vulnerabilities", "NO") == "YES" for r in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ["#e74c3c" if v else "#3498db" for v in has_vuln]
    bars = ax.barh(range(len(names)), dep_counts, color=colors, edgecolor="#2c3e50", height=0.6)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("Number of Dependent Crates")
    ax.set_title("Dependency Network Centrality: Most Depended-Upon Crates\n(Red = has vulnerabilities)")
    for i, c in enumerate(dep_counts):
        ax.text(c + max(dep_counts)*0.01, i, str(c), va="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "08_dependency_centrality.png"))
    plt.close(fig)
    print(f"[PLOT] 08_dependency_centrality.png")


# =============================================================================
# PLOT 9: Ecosystem Risk - Depended-Upon Vulnerable Crates
# =============================================================================

def plot_ecosystem_risk(rows, out_dir):
    if len(rows) < 2:
        return
    rows = sorted(rows, key=lambda r: safe_float(r.get("ecosystem_risk_score", 0)), reverse=True)[:20]
    names = [r.get("dependency_name", "?")[:25] for r in rows]
    scores = [safe_float(r.get("ecosystem_risk_score", 0)) for r in rows]
    dependents = [safe_int(r.get("dependents_count", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(12, 6))
    norm_scores = [math.log10(s + 1) for s in scores]
    colors = plt.cm.Reds([0.3 + 0.7 * (i / len(names)) for i in range(len(names))])
    bars = ax.barh(range(len(names)), norm_scores, color=colors, edgecolor="#922b21", height=0.6)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("Ecosystem Risk (log10 scale)")
    ax.set_title("Highest Ecosystem Risk: Vulnerable + Widely Depended Upon Crates")
    for i, (s, d) in enumerate(zip(scores, dependents)):
        ax.text(norm_scores[i] + 0.02, i, f"score={s:.0f}  ({d} deps)", va="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "09_ecosystem_risk.png"))
    plt.close(fig)
    print(f"[PLOT] 09_ecosystem_risk.png")


# =============================================================================
# PLOT 10: Temporal - Crates Created per Year vs Vulnerability Rate
# =============================================================================

def plot_temporal_creation(rows, out_dir):
    if not rows:
        return
    years = [safe_int(r.get("creation_year", 0)) for r in rows if safe_int(r.get("creation_year", 0)) > 2000]
    counts = [safe_int(r.get("crates_created", 0)) for r in rows if safe_int(r.get("creation_year", 0)) > 2000]
    vuln_pcts = [safe_float(r.get("pct_with_vulns", 0)) for r in rows if safe_int(r.get("creation_year", 0)) > 2000]

    fig, ax1 = plt.subplots(figsize=(11, 5))
    ax1.bar(years, counts, color="#3498db", alpha=0.7, label="Crates Created")
    ax1.set_xlabel("Year")
    ax1.set_ylabel("Number of Crates Created", color="#2980b9")
    ax1.tick_params(axis="y", labelcolor="#2980b9")

    ax2 = ax1.twinx()
    ax2.plot(years, vuln_pcts, color="#e74c3c", marker="o", linewidth=2, label="% Vulnerable")
    ax2.set_ylabel("% of Crates with Vulns", color="#c0392b")
    ax2.tick_params(axis="y", labelcolor="#c0392b")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", fontsize=8)

    ax1.set_title("Crate Creation Rate vs Vulnerability Prevalence Over Time")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "10_temporal_creation_vs_vulns.png"))
    plt.close(fig)
    print(f"[PLOT] 10_temporal_creation_vs_vulns.png")


# =============================================================================
# PLOT 11: Crate Age vs Vulnerability (Grouped Bar)
# =============================================================================

def plot_crate_age_vulns(rows, out_dir):
    if not rows:
        return
    ages = [r.get("crate_age", "?") for r in rows]
    counts = [safe_int(r.get("crate_count", 0)) for r in rows]
    vuln_pcts = [safe_float(r.get("pct_vulnerable", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(ages))
    width = 0.6
    bars = ax.bar(x, vuln_pcts, width, color="#e74c3c", edgecolor="#c0392b")
    ax.set_xticks(x)
    ax.set_xticklabels(ages, fontsize=9)
    ax.set_ylabel("% of Crates with Vulnerabilities")
    ax.set_title("Vulnerability Rate by Crate Age")
    for i, (p, c) in enumerate(zip(vuln_pcts, counts)):
        ax.text(i, p + 0.5, f"{p}%\n({c} crates)", ha="center", fontsize=7)
    ax.set_ylim(0, max(vuln_pcts) * 1.3 if vuln_pcts else 10)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "11_crate_age_vs_vulns.png"))
    plt.close(fig)
    print(f"[PLOT] 11_crate_age_vs_vulns.png")


# =============================================================================
# PLOT 12: Executables Prevalence by Download Bracket
# =============================================================================

def plot_executables_by_downloads(rows, out_dir):
    if not rows:
        return
    brackets = [r.get("download_bracket", "?") for r in rows]
    total = [safe_int(r.get("total_crates", 0)) for r in rows]
    exec_counts = [safe_int(r.get("crates_with_executables", 0)) for r in rows]
    pcts = [safe_float(r.get("pct_with_executables", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(brackets))
    width = 0.35
    ax.bar(x + width/2, total, width, label="All Crates", color="#3498db", edgecolor="#2c3e50")
    ax.bar(x - width/2, exec_counts, width, label="With Executables", color="#e74c3c", edgecolor="#2c3e50")
    ax.set_xticks(x)
    ax.set_xticklabels(brackets, rotation=30, fontsize=8, ha="right")
    ax.set_ylabel("Number of Crates")
    ax.set_title("Executable Files Prevalence by Download Bracket")
    ax.legend(fontsize=8)
    for i, p in enumerate(pcts):
        ax.text(i, max(total[i], exec_counts[i]) + max(total)*0.02,
                f"{p}% have\n executables", ha="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "12_executables_by_downloads.png"))
    plt.close(fig)
    print(f"[PLOT] 12_executables_by_downloads.png")


# =============================================================================
# PLOT 13: Analysis Timing Breakdown (Stacked Bar)
# =============================================================================

def plot_analysis_timing(out_dir):
    rows = run_raw_query("""
        SELECT
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY COALESCE(cargo_audit_duration_ms,0)) AS p50_cargo_audit,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY COALESCE(gitleaks_duration_ms,0)) AS p50_gitleaks,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY COALESCE(build_rs_analysis_duration_ms,0)) AS p50_build_rs,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY COALESCE(llm_analysis_duration_ms,0)) AS p50_llm,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY COALESCE(executable_check_duration_ms,0)) AS p50_exec_check,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY COALESCE(download_duration_ms,0)) AS p50_download,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(cargo_audit_duration_ms,0)) AS p95_cargo_audit,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(gitleaks_duration_ms,0)) AS p95_gitleaks,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(build_rs_analysis_duration_ms,0)) AS p95_build_rs,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(llm_analysis_duration_ms,0)) AS p95_llm,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(executable_check_duration_ms,0)) AS p95_exec_check,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(download_duration_ms,0)) AS p95_download
        FROM analysis_metrics
    """)
    if not rows:
        return
    r = rows[0]
    steps = ["Download", "Exec Check", "Cargo Audit", "Gitleaks", "Build.rs", "LLM"]
    p50 = [safe_float(r.get("p50_download", 0)),
           safe_float(r.get("p50_exec_check", 0)),
           safe_float(r.get("p50_cargo_audit", 0)),
           safe_float(r.get("p50_gitleaks", 0)),
           safe_float(r.get("p50_build_rs", 0)),
           safe_float(r.get("p50_llm", 0))]
    p95 = [safe_float(r.get("p95_download", 0)),
           safe_float(r.get("p95_exec_check", 0)),
           safe_float(r.get("p95_cargo_audit", 0)),
           safe_float(r.get("p95_gitleaks", 0)),
           safe_float(r.get("p95_build_rs", 0)),
           safe_float(r.get("p95_llm", 0))]

    if all(v == 0 for v in p50):
        print("[SKIP] No timing data available")
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(steps))
    width = 0.35
    ax.bar(x - width/2, p50, width, label="Median (p50)", color="#2ecc71", edgecolor="#27ae60")
    ax.bar(x + width/2, p95, width, label="p95", color="#e74c3c", edgecolor="#c0392b")
    ax.set_xticks(x)
    ax.set_xticklabels(steps, fontsize=9)
    ax.set_ylabel("Duration (ms)")
    ax.set_title("Per-Crate Analysis Timing Breakdown (Median vs p95)")
    ax.legend(fontsize=8)
    for i, (v50, v95) in enumerate(zip(p50, p95)):
        if v50 > 0:
            ax.text(i - width/2, v50 + max(p95)*0.02, f"{v50:.0f}", ha="center", fontsize=6)
        if v95 > 0:
            ax.text(i + width/2, v95 + max(p95)*0.02, f"{v95:.0f}", ha="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "13_analysis_timing.png"))
    plt.close(fig)
    print(f"[PLOT] 13_analysis_timing.png")


# =============================================================================
# PLOT 15: Download Velocity vs Vulnerability Rate
# =============================================================================

def plot_download_velocity(rows, out_dir):
    if not rows:
        return
    velocities = [r.get("download_velocity", "?") for r in rows]
    counts = [safe_int(r.get("crate_count", 0)) for r in rows]
    pcts = [safe_float(r.get("pct_vulnerable", 0)) for r in rows]
    avg_vulns = [safe_float(r.get("avg_vulns_per_crate", 0)) for r in rows]

    fig, ax1 = plt.subplots(figsize=(10, 5))
    x = np.arange(len(velocities))
    ax1.bar(x, counts, color="#3498db", alpha=0.6, label="Crate Count")
    ax1.set_ylabel("Number of Crates")
    ax1.set_xticks(x)
    ax1.set_xticklabels(velocities, rotation=20, fontsize=7, ha="right")

    ax2 = ax1.twinx()
    ax2.plot(x, pcts, "o-", color="#e74c3c", linewidth=2, label="% Vulnerable")
    ax2.plot(x, avg_vulns, "s--", color="#e67e22", linewidth=2, label="Avg Vulns/Crate")
    ax2.set_ylabel("% Vulnerable / Avg Vulns")
    ax2.set_ylim(0, max(max(pcts), max(avg_vulns)) * 1.3 if any(v > 0 for v in pcts + avg_vulns) else 10)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", fontsize=8)
    ax1.set_title("Download Velocity vs Vulnerability Rate")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "15_download_velocity.png"))
    plt.close(fig)
    print(f"[PLOT] 15_download_velocity.png")


# =============================================================================
# PLOT 16: Dependency Count Distribution
# =============================================================================

def plot_dependency_distribution(rows, out_dir):
    if not rows:
        return
    brackets = [r.get("dep_count_bracket", "?") for r in rows]
    counts = [safe_int(r.get("crate_count", 0)) for r in rows]
    pcts = [safe_float(r.get("pct_of_total", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(10, 5))
    colors = plt.cm.Blues([0.3 + 0.7 * (i / max(len(brackets) - 1, 1)) for i in range(len(brackets))])
    bars = ax.bar(range(len(brackets)), counts, color=colors, edgecolor="#2c3e50")
    ax.set_xticks(range(len(brackets)))
    ax.set_xticklabels(brackets, rotation=30, fontsize=8, ha="right")
    ax.set_ylabel("Number of Crates")
    ax.set_title("Dependency Count Distribution Across Ecosystem")
    for i, (c, p) in enumerate(zip(counts, pcts)):
        ax.text(i, c + max(counts) * 0.02, f"{c:,}\n({p}%)", ha="center", fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "16_dependency_distribution.png"))
    plt.close(fig)
    print(f"[PLOT] 16_dependency_distribution.png")


# =============================================================================
# PLOT 17: Build.rs Entropy Distribution
# =============================================================================

def plot_build_rs_entropy(rows, out_dir):
    if not rows:
        return
    rows_filtered = [r for r in rows if safe_float(r.get("bucket_lower", 0)) > 0]
    if not rows_filtered:
        return
    lowers = [safe_float(r.get("bucket_lower", 0)) for r in rows_filtered]
    counts = [safe_int(r.get("crate_count", 0)) for r in rows_filtered]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(lowers, counts, width=0.35, color="#8e44ad", edgecolor="#6c3483", align="edge")
    ax.set_xlabel("Entropy Score")
    ax.set_ylabel("Number of Crates")
    ax.set_title("Distribution of build.rs Entropy Scores (non-zero)")
    ax.axvline(x=4.5, color="#e74c3c", linestyle="--", alpha=0.7, label="High entropy threshold (4.5)")
    for x, c in zip(lowers, counts):
        if c > 0:
            ax.text(x + 0.17, c + max(counts) * 0.02, str(c), ha="center", fontsize=7)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "17_build_rs_entropy.png"))
    plt.close(fig)
    print(f"[PLOT] 17_build_rs_entropy.png")


# =============================================================================
# PLOT 18: Vulnerability Prevalence by Download Bracket
# =============================================================================

def plot_vulns_by_download_bracket(out_dir):
    rows = run_raw_query("""
        SELECT 
            CASE 
                WHEN c.crate_downloads >= 1000000 THEN '>= 1M'
                WHEN c.crate_downloads >= 100000 THEN '100K - 1M'
                WHEN c.crate_downloads >= 10000 THEN '10K - 100K'
                WHEN c.crate_downloads >= 1000 THEN '1K - 10K'
                WHEN c.crate_downloads >= 100 THEN '100 - 1K'
                ELSE '< 100'
            END AS download_bracket,
            COUNT(*) AS total_crates,
            COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0) AS crates_with_vulns,
            ROUND(COUNT(*) FILTER (WHERE car_vulns.vuln_count > 0)::numeric / COUNT(*) * 100, 1) AS pct_with_vulns,
            ROUND(AVG(car_vulns.vuln_count)::numeric, 2) AS avg_vulns_per_crate
        FROM crates c
        LEFT JOIN LATERAL (
            SELECT COUNT(*) AS vuln_count FROM cargo_audit_results car WHERE car.crate = c.id
        ) car_vulns ON TRUE
        GROUP BY download_bracket
        ORDER BY MIN(c.crate_downloads) DESC
    """)
    if not rows:
        return
    brackets = [r.get("download_bracket", "?") for r in rows]
    totals = [safe_int(r.get("total_crates", 0)) for r in rows]
    vuln_counts = [safe_int(r.get("crates_with_vulns", 0)) for r in rows]
    pcts = [safe_float(r.get("pct_with_vulns", 0)) for r in rows]
    avgs = [safe_float(r.get("avg_vulns_per_crate", 0)) for r in rows]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(brackets))
    width = 0.35
    ax.bar(x + width/2, totals, width, label="All Crates", color="#3498db", edgecolor="#2c3e50")
    ax.bar(x - width/2, vuln_counts, width, label="With Vulns", color="#e74c3c", edgecolor="#2c3e50")
    ax.set_xticks(x)
    ax.set_xticklabels(brackets, rotation=30, fontsize=8, ha="right")
    ax.set_ylabel("Number of Crates")
    ax.set_title("Vulnerability Prevalence by Download Bracket")
    ax.legend(fontsize=8)
    for i, (p, a) in enumerate(zip(pcts, avgs)):
        ax.text(i, max(totals[i], vuln_counts[i]) + max(totals) * 0.02,
                f"{p}% vuln\navg {a}/crate", ha="center", fontsize=6)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "18_vulns_by_download_bracket.png"))
    plt.close(fig)
    print(f"[PLOT] 18_vulns_by_download_bracket.png")


# =============================================================================
# PLOT 19: Secrets vs Vulnerabilities Overlap
# =============================================================================

def plot_secrets_vulns_overlap(rows, out_dir):
    if len(rows) < 3:
        return
    names = [r.get("crate_name", "?")[:20] for r in rows]
    secrets = [safe_int(r.get("secrets_count", 0)) for r in rows]
    vulns = [safe_int(r.get("vuln_count", 0)) for r in rows]
    downloads = [max(safe_int(r.get("crate_downloads", 0)), 1) for r in rows]

    fig, ax = plt.subplots(figsize=(10, 6))
    sizes = [max(np.log10(d) * 25, 4) for d in downloads]
    scatter = ax.scatter(vulns, secrets, s=sizes, c=np.log10(downloads),
                          cmap="viridis", alpha=0.7, edgecolors="black", linewidth=0.2)
    cbar = fig.colorbar(scatter, ax=ax, label="log10(Downloads)")
    ax.set_xlabel("Cargo-Audit Vulnerability Count")
    ax.set_ylabel("Gitleaks Secrets Count")
    ax.set_title("Compound Risk: Crates with Both Secrets Leaked and Known Vulns\n(bubble size = log10(downloads))")
    ax.set_xscale("symlog")
    ax.set_yscale("symlog")
    for i, name in enumerate(names[:12]):
        ax.annotate(name, (vulns[i], secrets[i]), fontsize=5, alpha=0.8,
                     xytext=(4, 4), textcoords="offset points")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "19_secrets_vs_vulns_overlap.png"))
    plt.close(fig)
    print(f"[PLOT] 19_secrets_vs_vulns_overlap.png")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Crate Security Analysis for Dissertation")
    parser.add_argument("--db", default=DEFAULT_DB, help="PostgreSQL connection string")
    parser.add_argument("--out-dir", default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--skip-plots", action="store_true", help="Skip generating plots")
    parser.add_argument("--only-sql", type=str, help="Run only a specific SQL file")
    args = parser.parse_args()

    os.makedirs(os.path.join(args.out_dir, "plots"), exist_ok=True)
    os.makedirs(os.path.join(args.out_dir, "data"), exist_ok=True)

    sql_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sql")
    sql_files = sorted(f for f in os.listdir(sql_dir) if f.endswith(".sql"))
    if args.only_sql:
        sql_files = [f for f in sql_files if args.only_sql in f]
        if not sql_files:
            print(f"[ERROR] No SQL file matching '{args.only_sql}' found in {sql_dir}")
            sys.exit(1)

    print(f"{'='*80}")
    print(f"  RUST CRATE ECOSYSTEM SECURITY ANALYSIS")
    print(f"  Database: {args.db}")
    print(f"  Output:   {args.out_dir}")
    print(f"  SQL files: {len(sql_files)}")
    print(f"{'='*80}\n")

    # --- Run each SQL file and print data tables ---
    all_results = {}
    for sf in sql_files:
        label = sf.replace(".sql", "")
        path = os.path.join(sql_dir, sf)
        print(f"[SQL] Running {sf} ...")
        rows = run_query(path, args.db)
        all_results[label] = rows
        print(f"       -> {len(rows)} rows returned\n")
        if rows:
            print_data_table(label.replace("_", " ").title(), rows)

    # --- Generate plots ---
    if not args.skip_plots:
        print(f"\n{'='*80}")
        print(f"  GENERATING PLOTS")
        print(f"{'='*80}\n")
        plots_dir = os.path.join(args.out_dir, "plots")

        # Plot 01
        if "01_most_vulnerable_crates" in all_results:
            plot_most_vulnerable_crates(all_results["01_most_vulnerable_crates"], plots_dir)

        # Plot 02
        if "02_vuln_per_download_ratio" in all_results:
            plot_vuln_per_download(all_results["02_vuln_per_download_ratio"], plots_dir)

        # Plot 03 - typosquat distribution
        if "03_typosquatting_analysis" in all_results:
            bucket_rows = [r for r in all_results["03_typosquatting_analysis"]
                          if "bucket_lower_bound" in r]
            if bucket_rows:
                plot_typosquat_distribution(bucket_rows, plots_dir)
            # Also print asymmetry data
            asymmetry_rows = [r for r in all_results["03_typosquatting_analysis"]
                             if "download_ratio" in r]
            if asymmetry_rows:
                print_data_table("Typosquat High Asymmetry Pairs", asymmetry_rows)

        # Plot 04
        if "04_secrets_leaked" in all_results:
            secret_rows = [r for r in all_results["04_secrets_leaked"] if "secret_type" in r]
            if secret_rows:
                plot_secret_types(secret_rows, plots_dir)

        # Plot 05
        if "05_build_rs_suspicious" in all_results:
            flag_rows = [r for r in all_results["05_build_rs_suspicious"] if "pattern" in r]
            if flag_rows:
                plot_build_rs_flags(flag_rows, plots_dir)

        # Plot 06
        if "06_llm_score_correlation" in all_results:
            agree_rows = [r for r in all_results["06_llm_score_correlation"] if "llm_category" in r]
            if agree_rows:
                plot_llm_agreement(agree_rows, plots_dir)

        # Plot 07 - severity distribution from ecosystem overview
        if "10_ecosystem_overview" in all_results:
            sev_rows = [r for r in all_results["10_ecosystem_overview"] if "severity_level" in r]
            if sev_rows:
                plot_severity_distribution(sev_rows, plots_dir)

        # Plot 08
        if "08_dependency_network" in all_results:
            dep_rows = [r for r in all_results["08_dependency_network"] if "dependents_count" in r
                       and "has_vulnerabilities" in r]
            if dep_rows:
                plot_dependency_centrality(dep_rows, plots_dir)

        # Plot 09 - ecosystem risk from dependency network
        if "08_dependency_network" in all_results:
            risk_rows = [r for r in all_results["08_dependency_network"] if "ecosystem_risk_score" in r]
            if risk_rows:
                plot_ecosystem_risk(risk_rows, plots_dir)

        # Plot 10
        if "09_temporal_analysis" in all_results:
            creation_rows = [r for r in all_results["09_temporal_analysis"] if "creation_year" in r]
            if creation_rows:
                plot_temporal_creation(creation_rows, plots_dir)

        # Plot 11 - crate age analysis
        if "09_temporal_analysis" in all_results:
            age_rows = [r for r in all_results["09_temporal_analysis"] if "crate_age" in r]
            if age_rows:
                plot_crate_age_vulns(age_rows, plots_dir)

        # Plot 12
        if "07_executable_files_analysis" in all_results:
            dl_rows = [r for r in all_results["07_executable_files_analysis"] if "download_bracket" in r]
            if dl_rows:
                plot_executables_by_downloads(dl_rows, plots_dir)

        # Plot 13 - timing
        plot_analysis_timing(plots_dir)

        # Plot 14 - secrets + vulns overlap scatter
        if "04_secrets_leaked" in all_results:
            overlap_rows = [r for r in all_results["04_secrets_leaked"]
                           if "crate_name" in r and "vuln_advisories" in r]
            if overlap_rows:
                plot_secrets_vulns_overlap(overlap_rows, plots_dir)

        # Plot 15
        if "09_temporal_analysis" in all_results:
            velocity_rows = [r for r in all_results["09_temporal_analysis"] if "download_velocity" in r]
            if velocity_rows:
                plot_download_velocity(velocity_rows, plots_dir)

        # Plot 16 - dependency count distribution
        if "08_dependency_network" in all_results:
            dep_dist_rows = [r for r in all_results["08_dependency_network"] if "dep_count_bracket" in r]
            if dep_dist_rows:
                plot_dependency_distribution(dep_dist_rows, plots_dir)

        # Plot 17 - build.rs entropy distribution
        if "05_build_rs_suspicious" in all_results:
            entropy_rows = [r for r in all_results["05_build_rs_suspicious"] if "entropy_bucket" in r]
            if entropy_rows:
                plot_build_rs_entropy(entropy_rows, plots_dir)

        # Plot 18 - vulnerability prevalence by download bracket
        plot_vulns_by_download_bracket(plots_dir)

    print(f"\n{'='*80}")
    print(f"  ANALYSIS COMPLETE")
    print(f"  Data printed above. Plots saved to: {os.path.join(args.out_dir, 'plots')}/")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()

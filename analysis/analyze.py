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
# PLOT 2: Ecosystem-Wide Vulnerability & Dependency Statistics
# =============================================================================

def plot_vuln_per_download(rows, out_dir):
    if not rows:
        return

    stats_rows = [r for r in rows if "total_crates" in r]
    vuln_dist_rows = [r for r in rows if "vuln_count_bracket" in r]
    dep_dist_rows = [r for r in rows if "dep_count_bracket" in r]
    conc_rows = [r for r in rows if "concentration_bucket" in r]

    fig = plt.figure(figsize=(14, 9))
    gs = fig.add_gridspec(2, 3, height_ratios=[1, 1.2], hspace=0.45, wspace=0.4)

    # --- Top-left: Ecosystem summary stats panel ---
    ax_stats = fig.add_subplot(gs[0, 0])
    ax_stats.axis("off")
    if stats_rows:
        r = stats_rows[0]
        total = safe_int(r.get("total_crates", 0))
        scanned = safe_int(r.get("successfully_scanned", 0))
        failed = safe_int(r.get("failed_scans", 0))
        in_scan = safe_int(r.get("in_scan_results", 0))
        never = total - in_scan
        stats_text = (
            f"Ecosystem Vulnerability Statistics\n"
            f"{'─' * 38}\n"
            f"  Total crates in database:   {total:>8,}\n"
            f"  In scan_results (attempted):{in_scan:>8,}\n"
            f"  Successfully scanned:       {scanned:>8,}\n"
            f"  Failed scans (score = -1):  {failed:>8,}\n"
            f"  Never attempted:            {never:>8,}\n"
            f"{'─' * 38}\n"
            f"  Crates with vulns:          {safe_int(r.get('crates_with_vulns', 0)):>8,}\n"
            f"  % of scanned vulnerable:    {safe_float(r.get('pct_vuln_crates', 0)):>7}%\n"
            f"{'─' * 38}\n"
            f"  Max vulns in a single crate: {safe_int(r.get('max_vulns_in_crate', 0)):>6,}\n"
            f"  Mean vulns per crate:       {safe_float(r.get('mean_vulns_per_crate', 0)):>8.2f}\n"
            f"  Median vulns per crate:     {safe_float(r.get('median_vulns_per_crate', 0)):>8.1f}\n"
            f"{'─' * 38}\n"
            f"  Mean dependencies per crate:{safe_float(r.get('mean_deps_per_crate', 0)):>8.2f}\n"
            f"  Median dependencies/crate:  {safe_float(r.get('median_deps_per_crate', 0)):>8.1f}"
        )
        ax_stats.text(0.02, 0.98, stats_text, transform=ax_stats.transAxes,
                      fontsize=7.8, verticalalignment="top", fontfamily="monospace",
                      bbox=dict(boxstyle="round,pad=0.5", facecolor="#f8f9fa", edgecolor="#dee2e6"))
    ax_stats.set_title("Ecosystem Overview", fontsize=11, fontweight="bold")

    # --- Top-middle: Donut chart of vuln vs non-vuln (of scanned) ---
    ax_donut = fig.add_subplot(gs[0, 1])
    if stats_rows:
        r = stats_rows[0]
        vuln_crates = safe_int(r.get("crates_with_vulns", 0))
        scanned = safe_int(r.get("successfully_scanned", 1))
        clean_scanned = scanned - vuln_crates
        sizes = [vuln_crates, clean_scanned]
        labels = [f"Vulnerable\n({vuln_crates:,})", f"No vulns found\n({clean_scanned:,})"]
        colors = ["#e74c3c", "#2ecc71"]
        wedges, texts = ax_donut.pie(
            sizes, labels=None, startangle=90, colors=colors,
            wedgeprops={"edgecolor": "white", "linewidth": 1.5, "width": 0.4}
        )
        ax_donut.legend(wedges, labels, loc="lower center", fontsize=7,
                        bbox_to_anchor=(0.5, -0.15), ncol=2)
        ax_donut.set_title("Scanned Crates:\nVulnerable vs Clean", fontsize=10, fontweight="bold")

    # --- Top-right: Vulnerability concentration ---
    ax_conc = fig.add_subplot(gs[0, 2])
    if conc_rows:
        buckets = [r.get("concentration_bucket", "?") for r in conc_rows]
        pcts = [safe_float(r.get("pct_of_all_vulns", 0)) for r in conc_rows]
        colors_conc = ["#922b21", "#c0392b", "#e74c3c", "#f5b7b1"]
        bars = ax_conc.barh(range(len(buckets)), pcts, color=colors_conc,
                            edgecolor="#2c3e50", height=0.55)
        ax_conc.set_yticks(range(len(buckets)))
        ax_conc.set_yticklabels(buckets, fontsize=8)
        ax_conc.invert_yaxis()
        ax_conc.set_xlabel("% of All Vulnerabilities")
        ax_conc.set_title("Vulnerability Concentration", fontsize=10, fontweight="bold")
        for i, p in enumerate(pcts):
            ax_conc.text(p + 1, i, f"{p}%", va="center", fontsize=8, fontweight="bold")

    # --- Bottom-left: Vuln count distribution histogram ---
    ax_vuln = fig.add_subplot(gs[1, 0])
    if vuln_dist_rows:
        labels_v = [r.get("vuln_count_bracket", "?") for r in vuln_dist_rows]
        counts_v = [safe_int(r.get("crate_count", 0)) for r in vuln_dist_rows]
        colors_v = plt.cm.Reds([0.25 + 0.75 * (i / max(len(labels_v) - 1, 1)) for i in range(len(labels_v))])
        ax_vuln.bar(range(len(labels_v)), counts_v, color=colors_v, edgecolor="#922b21")
        ax_vuln.set_xticks(range(len(labels_v)))
        ax_vuln.set_xticklabels(labels_v, fontsize=8)
        ax_vuln.set_ylabel("Number of Scanned Crates")
        ax_vuln.set_title("Vulnerability Count Distribution", fontsize=10, fontweight="bold")
        for i, c in enumerate(counts_v):
            ax_vuln.text(i, c + max(counts_v) * 0.02, f"{c:,}", ha="center", fontsize=7)

    # --- Bottom-middle: Dependency count distribution histogram ---
    ax_dep = fig.add_subplot(gs[1, 1])
    if dep_dist_rows:
        labels_d = [r.get("dep_count_bracket", "?") for r in dep_dist_rows]
        counts_d = [safe_int(r.get("crate_count", 0)) for r in dep_dist_rows]
        colors_d = plt.cm.Blues([0.25 + 0.75 * (i / max(len(labels_d) - 1, 1)) for i in range(len(labels_d))])
        ax_dep.bar(range(len(labels_d)), counts_d, color=colors_d, edgecolor="#2471a3")
        ax_dep.set_xticks(range(len(labels_d)))
        ax_dep.set_xticklabels(labels_d, rotation=30, fontsize=7, ha="right")
        ax_dep.set_ylabel("Number of Scanned Crates")
        ax_dep.set_title("Dependency Count Distribution", fontsize=10, fontweight="bold")
        for i, c in enumerate(counts_d):
            ax_dep.text(i, c + max(counts_d) * 0.02, f"{c:,}", ha="center", fontsize=7)

    # --- Bottom-right: Downloads vs Vulns scatter (scanned crates only) ---
    ax_scatter = fig.add_subplot(gs[1, 2])
    scatter_rows = run_raw_query("""
        SELECT
            c.crate_downloads,
            COUNT(car.id) AS vuln_count
        FROM crates c
        INNER JOIN scan_results sr ON c.id = sr.id AND sr.llm_malicious_score != -1
        LEFT JOIN cargo_audit_results car ON c.id = car.crate
        GROUP BY c.id, c.crate_downloads
    """)
    if scatter_rows and len(scatter_rows) > 10:
        dls = np.array([max(safe_int(r.get("crate_downloads", 0)), 1) for r in scatter_rows])
        vulns_arr = np.array([safe_int(r.get("vuln_count", 0)) for r in scatter_rows])
        mask = dls > 0
        ax_scatter.hexbin(np.log10(dls[mask]), vulns_arr[mask], gridsize=30,
                           cmap="YlOrRd", mincnt=1, edgecolors="none")
        ax_scatter.set_xlabel("Downloads (log10)")
        ax_scatter.set_ylabel("Vuln Count")
        ax_scatter.set_title("Vulns vs Downloads\n(scanned crates)", fontsize=9, fontweight="bold")

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

    fig, ax = plt.subplots(figsize=(12, max(6, len(types) * 0.25)))
    colors = plt.cm.Reds([0.3 + 0.7 * (i / max(len(types) - 1, 1)) for i in range(len(types))])
    bars = ax.barh(range(len(types)), counts, color=colors, edgecolor="#922b21", height=0.6)
    ax.set_yticks(range(len(types)))
    ax.set_yticklabels(types, fontsize=7)
    ax.invert_yaxis()
    ax.set_xlabel("Number of Findings (log scale)")
    ax.set_xscale("log")
    ax.set_title("Secrets Leaked: All Gitleaks Rule Matches (non-test/non-example locations)")
    for i, c in enumerate(counts):
        ax.text(c * 1.15, i, f"{c:,}", va="center", fontsize=7)
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
    fig.savefig(os.path.join(out_dir, "06_severity_distribution.png"))
    plt.close(fig)
    print(f"[PLOT] 06_severity_distribution.png")


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
    fig.savefig(os.path.join(out_dir, "07_dependency_centrality.png"))
    plt.close(fig)
    print(f"[PLOT] 07_dependency_centrality.png")


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
    fig.savefig(os.path.join(out_dir, "08_ecosystem_risk.png"))
    plt.close(fig)
    print(f"[PLOT] 08_ecosystem_risk.png")


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
    fig.savefig(os.path.join(out_dir, "09_temporal_creation_vs_vulns.png"))
    plt.close(fig)
    print(f"[PLOT] 09_temporal_creation_vs_vulns.png")


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
    fig.savefig(os.path.join(out_dir, "10_crate_age_vs_vulns.png"))
    plt.close(fig)
    print(f"[PLOT] 10_crate_age_vs_vulns.png")


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
    fig.savefig(os.path.join(out_dir, "11_executables_by_downloads.png"))
    plt.close(fig)
    print(f"[PLOT] 11_executables_by_downloads.png")


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
    fig.savefig(os.path.join(out_dir, "12_analysis_timing.png"))
    plt.close(fig)
    print(f"[PLOT] 12_analysis_timing.png")


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
    fig.savefig(os.path.join(out_dir, "13_download_velocity.png"))
    plt.close(fig)
    print(f"[PLOT] 13_download_velocity.png")


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
    fig.savefig(os.path.join(out_dir, "14_dependency_distribution.png"))
    plt.close(fig)
    print(f"[PLOT] 14_dependency_distribution.png")


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
    fig.savefig(os.path.join(out_dir, "15_build_rs_entropy.png"))
    plt.close(fig)
    print(f"[PLOT] 15_build_rs_entropy.png")


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
    fig.savefig(os.path.join(out_dir, "16_vulns_by_download_bracket.png"))
    plt.close(fig)
    print(f"[PLOT] 16_vulns_by_download_bracket.png")


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

    # --- Scan status summary ---
    scan_summary = run_raw_query("""
        SELECT
            (SELECT COUNT(*) FROM crates) AS total_crates,
            (SELECT COUNT(*) FROM scan_results) AS crates_with_scan_results,
            (SELECT COUNT(*) FROM scan_results WHERE llm_malicious_score != -1) AS successfully_scanned,
            (SELECT COUNT(*) FROM scan_results WHERE llm_malicious_score = -1) AS failed_scans
    """)
    if scan_summary:
        r = scan_summary[0]
        total = safe_int(r.get("total_crates", 0))
        with_results = safe_int(r.get("crates_with_scan_results", 0))
        scanned = safe_int(r.get("successfully_scanned", 0))
        failed = safe_int(r.get("failed_scans", 0))
        never_attempted = total - with_results
        print(f"\n{'='*80}")
        print(f"  SCAN COVERAGE SUMMARY")
        print(f"{'='*80}")
        print(f"  Total crates in database:       {total:>8,}")
        print(f"  Crates with scan results:       {with_results:>8,}  ({with_results/total*100:.1f}%)")
        print(f"    Successfully scanned:         {scanned:>8,}  ({scanned/total*100:.1f}%)")
        print(f"    Failed (score = -1):          {failed:>8,}  ({failed/total*100:.1f}%)")
        print(f"  Never attempted:                {never_attempted:>8,}  ({never_attempted/total*100:.1f}%)")
        print(f"{'='*80}")
        print(f"  Using SUCCESSFULLY SCANNED crates as base for % calculations.")
        print(f"  Crates that failed or were never scanned have unknown vuln status.")
        print(f"{'='*80}\n")

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

        # Plot 06 - severity distribution from ecosystem overview
        if "10_ecosystem_overview" in all_results:
            sev_rows = [r for r in all_results["10_ecosystem_overview"] if "severity_level" in r]
            if sev_rows:
                plot_severity_distribution(sev_rows, plots_dir)

        # Plot 07 - dependency centrality
        if "08_dependency_network" in all_results:
            dep_rows = [r for r in all_results["08_dependency_network"] if "dependents_count" in r
                       and "has_vulnerabilities" in r]
            if dep_rows:
                plot_dependency_centrality(dep_rows, plots_dir)

        # Plot 08 - ecosystem risk
        if "08_dependency_network" in all_results:
            risk_rows = [r for r in all_results["08_dependency_network"] if "ecosystem_risk_score" in r]
            if risk_rows:
                plot_ecosystem_risk(risk_rows, plots_dir)

        # Plot 09 - temporal creation
        if "09_temporal_analysis" in all_results:
            creation_rows = [r for r in all_results["09_temporal_analysis"] if "creation_year" in r]
            if creation_rows:
                plot_temporal_creation(creation_rows, plots_dir)

        # Plot 10 - crate age
        if "09_temporal_analysis" in all_results:
            age_rows = [r for r in all_results["09_temporal_analysis"] if "crate_age" in r]
            if age_rows:
                plot_crate_age_vulns(age_rows, plots_dir)

        # Plot 11 - executable prevalence
        if "07_executable_files_analysis" in all_results:
            dl_rows = [r for r in all_results["07_executable_files_analysis"] if "download_bracket" in r]
            if dl_rows:
                plot_executables_by_downloads(dl_rows, plots_dir)

        # Plot 12 - analysis timing
        plot_analysis_timing(plots_dir)

        # Plot 13 - download velocity
        if "09_temporal_analysis" in all_results:
            velocity_rows = [r for r in all_results["09_temporal_analysis"] if "download_velocity" in r]
            if velocity_rows:
                plot_download_velocity(velocity_rows, plots_dir)

        # Plot 14 - dependency count distribution
        if "08_dependency_network" in all_results:
            dep_dist_rows = [r for r in all_results["08_dependency_network"] if "dep_count_bracket" in r]
            if dep_dist_rows:
                plot_dependency_distribution(dep_dist_rows, plots_dir)

        # Plot 15 - build.rs entropy distribution
        if "05_build_rs_suspicious" in all_results:
            entropy_rows = [r for r in all_results["05_build_rs_suspicious"] if "entropy_bucket" in r]
            if entropy_rows:
                plot_build_rs_entropy(entropy_rows, plots_dir)

        # Plot 16 - vulnerability prevalence by download bracket
        plot_vulns_by_download_bracket(plots_dir)

    print(f"\n{'='*80}")
    print(f"  ANALYSIS COMPLETE")
    print(f"  Data printed above. Plots saved to: {os.path.join(args.out_dir, 'plots')}/")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()

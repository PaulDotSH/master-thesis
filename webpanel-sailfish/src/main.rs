mod config;
mod db;
mod models;
mod schema;

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::NaiveDateTime;
use diesel::dsl::count_star;
use diesel::prelude::*;
use diesel::sql_types::{Double, Nullable};
use diesel_async::RunQueryDsl;
use sailfish::TemplateOnce;
use serde::Deserialize;
use std::sync::Arc;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::config::Config;
use crate::db::{create_pool, DbPool};
use crate::models::DashboardStats;
use crate::schema::{
    analysis_metrics, cargo_audit_results, crates, dependencies, gitleaks_results, scan_results,
    typosquat_results,
};

const DEFAULT_PAGE: i64 = 1;
const DEFAULT_PER_PAGE: i64 = 50;

fn fmt_num(n: i64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn fmt_dur(ms: Option<f64>) -> String {
    match ms {
        Some(v) if v >= 1000.0 => format!("{:.1}s", v / 1000.0),
        Some(v) => format!("{:.0}ms", v),
        None => "—".into(),
    }
}

fn fmt_opt_dur(ms: Option<i64>) -> String {
    match ms {
        Some(v) if v >= 1000 => format!("{:.1}s", v as f64 / 1000.0),
        Some(v) => format!("{}ms", v),
        None => "—".into(),
    }
}

fn risk_label(score: i16) -> &'static str {
    match score {
        0..=30 => "low",
        31..=60 => "medium",
        61..=80 => "high",
        _ => "critical",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max])
    } else {
        s.to_string()
    }
}

fn render_bool_badge(b: bool) -> String {
    let (cls, text) = if b {
        ("badge-yes", "Yes")
    } else {
        ("badge-no", "No")
    };
    format!("<span class=\"badge {}\">{}</span>", cls, text)
}

fn render_score_bar(score: i16, max: i16) -> String {
    let pct = (score as f64 / max as f64 * 100.0).min(100.0);
    let cls = risk_label(score);
    format!(
        "<div class=\"score-bar\"><div class=\"score-fill {}\" style=\"width:{:.0}%\"></div><span>{}</span></div>",
        cls, pct, score
    )
}

fn render_risk_badge(score: i16) -> String {
    let label = match score {
        0..=30 => "Low",
        31..=60 => "Medium",
        61..=80 => "High",
        _ => "Critical",
    };
    let cls = risk_label(score);
    format!("<span class=\"badge badge-{}\">{}</span>", cls, label)
}

fn build_base_query(params: &[(String, String)], exclude: &[&str]) -> String {
    let mut pairs: Vec<String> = Vec::new();
    for (k, v) in params {
        if !exclude.contains(&k.as_str()) && !v.is_empty() && k != "sort_by" && k != "sort_desc" {
            pairs.push(format!("{}={}", urlencoding(k), urlencoding(v)));
        }
    }
    pairs.join("&")
}

fn urlencoding(s: &str) -> String {
    s.replace('&', "%26")
        .replace('=', "%3D")
        .replace(' ', "+")
        .replace('<', "%3C")
        .replace('>', "%3E")
        .replace('"', "%22")
        .replace('#', "%23")
}

fn parse_opt_i16(s: &str) -> Option<i16> {
    if s.is_empty() { None } else { s.parse().ok() }
}
fn parse_opt_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

// ---- Template helpers for pagination rendering ----

#[allow(unused)]
struct PaginationHtml {
    html: String,
}
impl PaginationHtml {
    fn render(
        page: i64,
        total_pages: i64,
        total: i64,
        per_page: i64,
        base_query: &str,
        sort_by: &str,
        sort_desc: bool,
        ) -> String {
        if total_pages <= 1 && total <= per_page {
            return String::new();
        }
        let start = (page - 1) * per_page + 1;
        let end = ((page * per_page).min(total)).max(start);
        let mut parts: Vec<String> = Vec::new();
        if !base_query.is_empty() {
            parts.push(base_query.to_string());
        }
        if !sort_by.is_empty() {
            parts.push(format!("sort_by={}", sort_by));
            if sort_desc {
                parts.push("sort_desc=1".to_string());
            }
        }
        let qs = parts.join("&");
        let prefix = if qs.is_empty() {
            "?".to_string()
        } else {
            format!("?{}&", qs)
        };

        let mut h = format!(
            "<div class=\"pag\"><span class=\"pag-info\">{start}–{end} of {total}</span>",
            start = start,
            end = end,
            total = total
        );

        if page > 1 {
            h.push_str(&format!("<a href=\"{p}page=1\" class=\"pag-btn\">« First</a>", p = prefix));
            h.push_str(&format!("<a href=\"{p}page={pg}\" class=\"pag-btn\">‹ Prev</a>", p = prefix, pg = page - 1));
        }

        let win_start = ((page - 1) / 5) * 5 + 1;
        let win_end = (win_start + 4).min(total_pages);
        if win_start > 1 {
            h.push_str(&format!("<a href=\"{p}page={pg}\" class=\"pag-btn\">{pg}</a>", p = prefix, pg = win_start - 1));
            if win_start > 2 {
                h.push_str("<span class=\"pag-ell\">…</span>");
            }
        }
        for pg in win_start..=win_end {
            if pg == page {
                h.push_str(&format!("<span class=\"pag-cur\">{}</span>", pg));
            } else {
                h.push_str(&format!("<a href=\"{p}page={pg}\" class=\"pag-btn\">{pg}</a>", p = prefix, pg = pg));
            }
        }
        if win_end < total_pages {
            if win_end < total_pages - 1 {
                h.push_str("<span class=\"pag-ell\">…</span>");
            }
            h.push_str(&format!("<a href=\"{p}page={pg}\" class=\"pag-btn\">{pg}</a>", p = prefix, pg = total_pages));
        }

        if page < total_pages {
            h.push_str(&format!("<a href=\"{p}page={pg}\" class=\"pag-btn\">Next ›</a>", p = prefix, pg = page + 1));
            h.push_str(&format!("<a href=\"{p}page={pg}\" class=\"pag-btn\">Last »</a>", p = prefix, pg = total_pages));
        }

        h.push_str("</div>");
        h
    }
}

// ====== TEMPLATE STRUCTS ======

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/dashboard.html")]
struct DashboardTmpl {
    total_crates: String,
    total_dependencies: String,
    total_scanned: String,
    malicious_count: String,
    high_risk_count: String,
    vulnerabilities_count: String,
    secrets_found: String,
    typosquat_count: String,
    avg_duration: String,
    latest_duration: String,
    risk_bars: Vec<RiskBar>,
    build_rs_bars: Vec<BarItem>,
    top_crates: Vec<LabelVal>,
    gitleaks_bars: Vec<BarItem>,
    current_route: String,
}

#[allow(unused)]
struct RiskBar {
    label: String,
    count: String,
    pct: f64,
    cls: String,
}
#[allow(unused)]
struct BarItem {
    label: String,
    count: String,
    pct: f64,
    cls: String,
}
#[allow(unused)]
struct LabelVal {
    label: String,
    value: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/crates.html")]
struct CratesTmpl {
    current_route: String,
    rows: Vec<CrateRow>,
    pagination: String,
    search: String,
    min_downloads: String,
    max_downloads: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct CrateRow {
    id: String,
    name: String,
    repository: String,
    repo_short: String,
    downloads: String,
    created: String,
    updated: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/dependencies.html")]
struct DepsTmpl {
    current_route: String,
    rows: Vec<DepRow>,
    pagination: String,
    crate_name: String,
    crate_id: String,
    dependency_id: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct DepRow {
    crate_id: String,
    crate_name: String,
    dependency_id: String,
    dependency_name: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/vulnerabilities.html")]
struct VulnsTmpl {
    current_route: String,
    rows: Vec<VulnRow>,
    pagination: String,
    crate_name: String,
    rustsec_id: String,
    min_severity: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct VulnRow {
    rustsec_id: String,
    crate_name: String,
    crate_id: String,
    severity_badge: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/secrets.html")]
struct SecretsTmpl {
    current_route: String,
    rows: Vec<SecretRow>,
    pagination: String,
    crate_name: String,
    rule_id: String,
    min_entropy: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct SecretRow {
    crate_name: String,
    rule_id: String,
    secret_short: String,
    loc: String,
    entropy: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/typosquat.html")]
struct TyposquatTmpl {
    current_route: String,
    rows: Vec<TypoRow>,
    pagination: String,
    crate_name: String,
    min_combined_score: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct TypoRow {
    crate_name: String,
    crate_id: String,
    similar_name: String,
    similar_id: String,
    combined_bar: String,
    levenshtein: String,
    jaro_winkler: String,
    keyboard: String,
    prefix: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/scan_results.html")]
struct ScanResultsTmpl {
    current_route: String,
    rows: Vec<ScanRow>,
    pagination: String,
    crate_name: String,
    min_llm_score: String,
    max_llm_score: String,
    has_malicious: String,
    has_vulns: String,
    build_net: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct ScanRow {
    id: String,
    crate_name: String,
    risk_bar: String,
    risk_badge: String,
    malicious_deps_badge: String,
    vulns_badge: String,
    network_badge: String,
    process_badge: String,
    executables_badge: String,
}

#[allow(unused)]
#[derive(TemplateOnce)]
#[template(path = "pages/metrics.html")]
struct MetricsTmpl {
    current_route: String,
    rows: Vec<MetricRow>,
    pagination: String,
    crate_name: String,
    crate_id: String,
    sort_by: String,
    sort_desc: bool,
    per_page: String,
    base_query_no_sort: String,
}

#[allow(unused)]
struct MetricRow {
    crate_id: String,
    crate_name: String,
    total_ms: String,
    download_ms: String,
    cargo_audit_ms: String,
    gitleaks_ms: String,
    executables_ms: String,
    build_rs_ms: String,
    llm_ms: String,
    worker_id: String,
    completed_at: String,
}

// ====== ERROR ======

struct AppError(anyhow::Error);
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Error: {:?}", self.0);
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Html(format!(
                "<h1>Internal Server Error</h1><pre>{}</pre>",
                self.0
            )),
        )
            .into_response()
    }
}
impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

fn base_no_sort(params: &[(String, String)]) -> String {
    build_base_query(params, &["page", "sort_by", "sort_desc"])
}

// ====== ROUTE HANDLERS ======

// ---- Dashboard ----

async fn dashboard(State(pool): State<Arc<DbPool>>) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let stats = DashboardStats {
        total_crates: crates::table.select(count_star()).first(&mut conn).await?,
        total_dependencies: dependencies::table
            .select(count_star())
            .first(&mut conn)
            .await?,
        total_scanned: scan_results::table.select(count_star()).first(&mut conn).await?,
        malicious_count: scan_results::table
            .filter(scan_results::has_malicious_dependencies.eq(true))
            .select(count_star())
            .first(&mut conn)
            .await?,
        high_risk_count: scan_results::table
            .filter(scan_results::llm_malicious_score.ge(70i16))
            .select(count_star())
            .first(&mut conn)
            .await?,
        vulnerabilities_count: cargo_audit_results::table
            .select(count_star())
            .first(&mut conn)
            .await?,
        secrets_found: gitleaks_results::table
            .select(count_star())
            .first(&mut conn)
            .await?,
        typosquat_count: typosquat_results::table
            .select(count_star())
            .first(&mut conn)
            .await?,
        avg_analysis_duration_ms: analysis_metrics::table
            .select(diesel::dsl::sql::<Nullable<Double>>(
                "AVG(total_duration_ms)::float8",
            ))
            .first(&mut conn)
            .await?,
        latest_analysis_duration_ms: analysis_metrics::table
            .select(analysis_metrics::total_duration_ms)
            .order(analysis_metrics::completed_at.desc())
            .first::<i64>(&mut conn)
            .await
            .ok(),
    };

    // risk distribution
    let scores: Vec<i16> = scan_results::table
        .select(scan_results::llm_malicious_score)
        .load(&mut conn)
        .await?;
    let total_risk = scores.len() as f64;
    let mut low = 0i64;
    let mut medium = 0i64;
    let mut high = 0i64;
    let mut critical = 0i64;
    for s in &scores {
        match s {
            0..=30 => low += 1,
            31..=60 => medium += 1,
            61..=80 => high += 1,
            _ => critical += 1,
        }
    }
    let risk_bars = vec![
        RiskBar { label: "Low (0–30)".into(), count: low.to_string(), pct: if total_risk > 0.0 { low as f64 / total_risk * 100.0 } else { 0.0 }, cls: "low".into() },
        RiskBar { label: "Medium (31–60)".into(), count: medium.to_string(), pct: if total_risk > 0.0 { medium as f64 / total_risk * 100.0 } else { 0.0 }, cls: "medium".into() },
        RiskBar { label: "High (61–80)".into(), count: high.to_string(), pct: if total_risk > 0.0 { high as f64 / total_risk * 100.0 } else { 0.0 }, cls: "high".into() },
        RiskBar { label: "Critical (81–100)".into(), count: critical.to_string(), pct: if total_risk > 0.0 { critical as f64 / total_risk * 100.0 } else { 0.0 }, cls: "critical".into() },
    ];

    // build.rs stats
    let scanned: i64 = stats.total_scanned;
    let scanned_f = scanned as f64;
    let br = vec![
        ("Network Calls", scan_results::table.filter(scan_results::build_rs_network_calls.eq(true)).select(count_star()).first::<i64>(&mut conn).await?),
        ("Link Directive", scan_results::table.filter(scan_results::build_rs_has_link_directive.eq(true)).select(count_star()).first::<i64>(&mut conn).await?),
        ("Process Spawning", scan_results::table.filter(scan_results::build_rs_has_process_spawning.eq(true)).select(count_star()).first::<i64>(&mut conn).await?),
        ("Raw IP", scan_results::table.filter(scan_results::build_rs_has_raw_ip.eq(true)).select(count_star()).first::<i64>(&mut conn).await?),
        ("Free TLDs", scan_results::table.filter(scan_results::build_rs_has_free_tlds.eq(true)).select(count_star()).first::<i64>(&mut conn).await?),
    ];
    let build_bars: Vec<BarItem> = br
        .iter()
        .map(|(l, c)| BarItem {
            label: l.to_string(),
            count: c.to_string(),
            pct: if scanned_f > 0.0 { *c as f64 / scanned_f * 100.0 } else { 0.0 },
            cls: "info".into(),
        })
        .collect();

    // top downloads
    let top: Vec<(i64, String, i64)> = crates::table
        .select((crates::id, crates::name, crates::crate_downloads))
        .order(crates::crate_downloads.desc())
        .limit(10)
        .load(&mut conn)
        .await?;
    let top_crates: Vec<LabelVal> = top
        .iter()
        .map(|(_, n, d)| LabelVal {
            label: n.clone(),
            value: fmt_num(*d),
        })
        .collect();

    // gitleaks rules
    let gl_rows: Vec<(String, i64)> = gitleaks_results::table
        .group_by(gitleaks_results::rule_id)
        .select((gitleaks_results::rule_id, count_star()))
        .order(count_star().desc())
        .limit(10)
        .load(&mut conn)
        .await?;
    let gl_max = gl_rows.get(0).map(|r| r.1 as f64).unwrap_or(1.0);
    let gitleaks_bars: Vec<BarItem> = gl_rows
        .iter()
        .map(|(r, c)| BarItem {
            label: r.clone(),
            count: c.to_string(),
            pct: if gl_max > 0.0 { *c as f64 / gl_max * 100.0 } else { 0.0 },
            cls: "info".into(),
        })
        .collect();

    let html = DashboardTmpl {
        total_crates: fmt_num(stats.total_crates),
        total_dependencies: fmt_num(stats.total_dependencies),
        total_scanned: fmt_num(stats.total_scanned),
        malicious_count: stats.malicious_count.to_string(),
        high_risk_count: fmt_num(stats.high_risk_count),
        vulnerabilities_count: fmt_num(stats.vulnerabilities_count),
        secrets_found: fmt_num(stats.secrets_found),
        typosquat_count: fmt_num(stats.typosquat_count),
        avg_duration: fmt_dur(stats.avg_analysis_duration_ms),
        latest_duration: fmt_opt_dur(stats.latest_analysis_duration_ms),
        risk_bars,
        build_rs_bars: build_bars,
        top_crates,
        gitleaks_bars,
        current_route: "/".into(),
    }
    .render_once()?;

    Ok(Html(html))
}

#[derive(Debug, Deserialize, Default)]
struct CrateFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    search: Option<String>,
    min_downloads: Option<String>,
    max_downloads: Option<String>,
}

impl CrateFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

fn base_from_filters(f: &CrateFilters) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(ref x) = f.search { if !x.is_empty() { v.push(("search".into(), x.clone())); } }
    if let Some(ref x) = f.min_downloads { if !x.is_empty() { v.push(("min_downloads".into(), x.clone())); } }
    if let Some(ref x) = f.max_downloads { if !x.is_empty() { v.push(("max_downloads".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { v.push(("per_page".into(), x.clone())); } }
    v
}

async fn crates_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<CrateFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let mut query = crates::table.into_boxed();
    let mut cnt_q = crates::table.into_boxed();

    if let Some(ref s) = f.search {
        let pat = format!("%{}%", s);
        query = query.filter(crates::name.ilike(pat.clone()));
        cnt_q = cnt_q.filter(crates::name.ilike(pat));
    }
    if let Some(ref s) = f.min_downloads {
        if let Ok(v) = s.parse::<i64>() {
            query = query.filter(crates::crate_downloads.ge(v));
            cnt_q = cnt_q.filter(crates::crate_downloads.ge(v));
        }
    }
    if let Some(ref s) = f.max_downloads {
        if let Ok(v) = s.parse::<i64>() {
            query = query.filter(crates::crate_downloads.le(v));
            cnt_q = cnt_q.filter(crates::crate_downloads.le(v));
        }
    }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "name" => if sort_desc { query.order(crates::name.desc()) } else { query.order(crates::name.asc()) },
        "downloads" | "crate_downloads" => if sort_desc { query.order(crates::crate_downloads.desc()) } else { query.order(crates::crate_downloads.asc()) },
        "created_at" | "crate_created_at" => if sort_desc { query.order(crates::crate_created_at.desc()) } else { query.order(crates::crate_created_at.asc()) },
        "updated_at" | "crate_updated_at" => if sort_desc { query.order(crates::crate_updated_at.desc()) } else { query.order(crates::crate_updated_at.asc()) },
        "repository" => if sort_desc { query.order(crates::repository.desc()) } else { query.order(crates::repository.asc()) },
        _ => if sort_desc { query.order(crates::id.desc()) } else { query.order(crates::id.asc()) },
    };

    let rows: Vec<models::Crate> = query.limit(per_page).offset(offset).load(&mut conn).await?;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let params = base_from_filters(&f);
    let bqs = base_no_sort(&params);

    let crate_rows: Vec<CrateRow> = rows.iter().map(|r| CrateRow {
        id: r.id.to_string(),
        name: r.name.clone(),
        repository: r.repository.clone(),
        repo_short: truncate(&r.repository, 60),
        downloads: fmt_num(r.crate_downloads),
        created: r.crate_created_at.format("%Y-%m-%d").to_string(),
        updated: r.crate_updated_at.format("%Y-%m-%d").to_string(),
    }).collect();

    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let html = CratesTmpl {
        current_route: "/crates".into(),
        rows: crate_rows,
        pagination: pag,
        search: f.search.unwrap_or_default(),
        min_downloads: f.min_downloads.unwrap_or_default(),
        max_downloads: f.max_downloads.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ---- Dependencies ----

#[derive(Debug, Deserialize, Default)]
struct DepFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    crate_name: Option<String>,
    crate_id: Option<String>,
    dependency_id: Option<String>,
}
impl DepFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

async fn deps_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<DepFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let (crate_c, dep_c) = diesel::alias!(crates as crate_c, crates as dep_c);

    let mut query = dependencies::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(dependencies::crate_id)))
        .inner_join(dep_c.on(dep_c.field(crates::id).eq(dependencies::dependency_id)))
        .into_boxed();
    let mut cnt_q = dependencies::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(dependencies::crate_id)))
        .inner_join(dep_c.on(dep_c.field(crates::id).eq(dependencies::dependency_id)))
        .into_boxed();

    if let Some(ref s) = f.crate_id {
        if let Ok(v) = s.parse::<i64>() { query = query.filter(dependencies::crate_id.eq(v)); cnt_q = cnt_q.filter(dependencies::crate_id.eq(v)); }
    }
    if let Some(ref s) = f.dependency_id {
        if let Ok(v) = s.parse::<i64>() { query = query.filter(dependencies::dependency_id.eq(v)); cnt_q = cnt_q.filter(dependencies::dependency_id.eq(v)); }
    }
    if let Some(ref s) = f.crate_name {
        let pat = format!("%{}%", s);
        query = query.filter(crate_c.field(crates::name).ilike(pat.clone()));
        cnt_q = cnt_q.filter(crate_c.field(crates::name).ilike(pat));
    }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "crate_name" => if sort_desc { query.order(crate_c.field(crates::name).desc()) } else { query.order(crate_c.field(crates::name).asc()) },
        "dependency_name" => if sort_desc { query.order(dep_c.field(crates::name).desc()) } else { query.order(dep_c.field(crates::name).asc()) },
        "crate_id" => if sort_desc { query.order(dependencies::crate_id.desc()) } else { query.order(dependencies::crate_id.asc()) },
        "dependency_id" => if sort_desc { query.order(dependencies::dependency_id.desc()) } else { query.order(dependencies::dependency_id.asc()) },
        _ => if sort_desc { query.order(dependencies::crate_id.desc()) } else { query.order(dependencies::crate_id.asc()) },
    };

    let results: Vec<(i64, i64, String, String)> = query
        .select((dependencies::crate_id, dependencies::dependency_id, crate_c.field(crates::name), dep_c.field(crates::name)))
        .limit(per_page).offset(offset).load(&mut conn).await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(ref x) = f.crate_name { if !x.is_empty() { params.push(("crate_name".into(), x.clone())); } }
    if let Some(ref x) = f.crate_id { if !x.is_empty() { params.push(("crate_id".into(), x.clone())); } }
    if let Some(ref x) = f.dependency_id { if !x.is_empty() { params.push(("dependency_id".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { params.push(("per_page".into(), x.clone())); } }
    let bqs = base_no_sort(&params);
    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let rows: Vec<DepRow> = results.iter().map(|(ci, di, cn, dn)| DepRow {
        crate_id: ci.to_string(),
        crate_name: cn.clone(),
        dependency_id: di.to_string(),
        dependency_name: dn.clone(),
    }).collect();

    let html = DepsTmpl {
        current_route: "/dependencies".into(),
        rows,
        pagination: pag,
        crate_name: f.crate_name.unwrap_or_default(),
        crate_id: f.crate_id.unwrap_or_default(),
        dependency_id: f.dependency_id.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ---- Vulnerabilities ----

#[derive(Debug, Deserialize, Default)]
struct CargoAuditFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    crate_name: Option<String>,
    crate_id: Option<String>,
    rustsec_id: Option<String>,
    min_severity: Option<String>,
}
impl CargoAuditFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

async fn vulns_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<CargoAuditFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let mut query = cargo_audit_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(cargo_audit_results::crate_)))
        .into_boxed();
    let mut cnt_q = cargo_audit_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(cargo_audit_results::crate_)))
        .into_boxed();

    if let Some(ref s) = f.crate_id {
        if let Ok(v) = s.parse::<i64>() { query = query.filter(cargo_audit_results::crate_.eq(v)); cnt_q = cnt_q.filter(cargo_audit_results::crate_.eq(v)); }
    }
    if let Some(ref s) = f.rustsec_id {
        let pat = format!("%{}%", s);
        query = query.filter(cargo_audit_results::rustsec_id.ilike(pat.clone()));
        cnt_q = cnt_q.filter(cargo_audit_results::rustsec_id.ilike(pat));
    }
    if let Some(ref s) = f.min_severity {
        if let Ok(v) = s.parse::<i16>() { query = query.filter(cargo_audit_results::severity.ge(v)); cnt_q = cnt_q.filter(cargo_audit_results::severity.ge(v)); }
    }
    if let Some(ref s) = f.crate_name {
        let pat = format!("%{}%", s);
        query = query.filter(crates::name.ilike(pat.clone()));
        cnt_q = cnt_q.filter(crates::name.ilike(pat));
    }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "crate_name" => if sort_desc { query.order(crates::name.desc()) } else { query.order(crates::name.asc()) },
        "rustsec_id" => if sort_desc { query.order(cargo_audit_results::rustsec_id.desc()) } else { query.order(cargo_audit_results::rustsec_id.asc()) },
        "severity" => if sort_desc { query.order(cargo_audit_results::severity.desc()) } else { query.order(cargo_audit_results::severity.asc()) },
        "crate_id" => if sort_desc { query.order(cargo_audit_results::crate_.desc()) } else { query.order(cargo_audit_results::crate_.asc()) },
        _ => if sort_desc { query.order(cargo_audit_results::id.desc()) } else { query.order(cargo_audit_results::id.asc()) },
    };

    let results: Vec<(Uuid, Option<i64>, String, Option<i16>, Option<String>)> = query
        .select((cargo_audit_results::id, cargo_audit_results::crate_, cargo_audit_results::rustsec_id, cargo_audit_results::severity, crates::name.nullable()))
        .limit(per_page).offset(offset).load(&mut conn).await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(ref x) = f.crate_name { if !x.is_empty() { params.push(("crate_name".into(), x.clone())); } }
    if let Some(ref x) = f.crate_id { if !x.is_empty() { params.push(("crate_id".into(), x.clone())); } }
    if let Some(ref x) = f.rustsec_id { if !x.is_empty() { params.push(("rustsec_id".into(), x.clone())); } }
    if let Some(ref x) = f.min_severity { if !x.is_empty() { params.push(("min_severity".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { params.push(("per_page".into(), x.clone())); } }
    let bqs = base_no_sort(&params);
    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let rows: Vec<VulnRow> = results.iter().map(|(_, crate_id, rustsec_id, severity, crate_name)| {
        let sev = severity.and_then(|s| if s == 0 { None } else { Some(s) });
        let (badge_cls, badge_label) = match sev {
            None => ("none", "None"),
            Some(1) => ("low", "Low"),
            Some(2) => ("medium", "Medium"),
            Some(3) => ("high", "High"),
            Some(4) | Some(5) => ("critical", "Critical"),
            _ => ("none", "Unknown"),
        };
        VulnRow {
            rustsec_id: rustsec_id.clone(),
            crate_name: crate_name.clone().unwrap_or_default(),
            crate_id: crate_id.map(|v| v.to_string()).unwrap_or_default(),
            severity_badge: format!("<span class=\"badge badge-{}\">{}</span>", badge_cls, badge_label),
        }
    }).collect();

    let html = VulnsTmpl {
        current_route: "/vulnerabilities".into(),
        rows,
        pagination: pag,
        crate_name: f.crate_name.unwrap_or_default(),
        rustsec_id: f.rustsec_id.unwrap_or_default(),
        min_severity: f.min_severity.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ---- Secrets ----

#[derive(Debug, Deserialize, Default)]
struct GitleaksFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    crate_name: Option<String>,
    crate_id: Option<String>,
    rule_id: Option<String>,
    min_entropy: Option<String>,
}
impl GitleaksFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

async fn secrets_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<GitleaksFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let mut query = gitleaks_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(gitleaks_results::crate_)))
        .into_boxed();
    let mut cnt_q = gitleaks_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(gitleaks_results::crate_)))
        .into_boxed();

    if let Some(ref s) = f.crate_id { if let Ok(v) = s.parse::<i64>() { query = query.filter(gitleaks_results::crate_.eq(v)); cnt_q = cnt_q.filter(gitleaks_results::crate_.eq(v)); } }
    if let Some(ref s) = f.rule_id { let pat = format!("%{}%", s); query = query.filter(gitleaks_results::rule_id.ilike(pat.clone())); cnt_q = cnt_q.filter(gitleaks_results::rule_id.ilike(pat)); }
    if let Some(ref s) = f.min_entropy { if let Ok(v) = s.parse::<f64>() { query = query.filter(gitleaks_results::entropy.ge(v)); cnt_q = cnt_q.filter(gitleaks_results::entropy.ge(v)); } }
    if let Some(ref s) = f.crate_name { let pat = format!("%{}%", s); query = query.filter(crates::name.ilike(pat.clone())); cnt_q = cnt_q.filter(crates::name.ilike(pat)); }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "crate_name" => if sort_desc { query.order(crates::name.desc()) } else { query.order(crates::name.asc()) },
        "rule_id" => if sort_desc { query.order(gitleaks_results::rule_id.desc()) } else { query.order(gitleaks_results::rule_id.asc()) },
        "entropy" => if sort_desc { query.order(gitleaks_results::entropy.desc()) } else { query.order(gitleaks_results::entropy.asc()) },
        "secret" => if sort_desc { query.order(gitleaks_results::secret.desc()) } else { query.order(gitleaks_results::secret.asc()) },
        _ => if sort_desc { query.order(gitleaks_results::id.desc()) } else { query.order(gitleaks_results::id.asc()) },
    };

    let results: Vec<(Uuid, Option<i64>, String, String, String, f64, Option<String>)> = query
        .select((gitleaks_results::id, gitleaks_results::crate_, gitleaks_results::rule_id, gitleaks_results::secret, gitleaks_results::loc, gitleaks_results::entropy, crates::name.nullable()))
        .limit(per_page).offset(offset).load(&mut conn).await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(ref x) = f.crate_name { if !x.is_empty() { params.push(("crate_name".into(), x.clone())); } }
    if let Some(ref x) = f.crate_id { if !x.is_empty() { params.push(("crate_id".into(), x.clone())); } }
    if let Some(ref x) = f.rule_id { if !x.is_empty() { params.push(("rule_id".into(), x.clone())); } }
    if let Some(ref x) = f.min_entropy { if !x.is_empty() { params.push(("min_entropy".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { params.push(("per_page".into(), x.clone())); } }
    let bqs = base_no_sort(&params);
    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let rows: Vec<SecretRow> = results.iter().map(|(_, _, rule_id, secret, loc, entropy, crate_name)| SecretRow {
        crate_name: crate_name.clone().unwrap_or_default(),
        rule_id: rule_id.clone(),
        secret_short: truncate(secret, 60),
        loc: truncate(loc, 60),
        entropy: format!("{:.2}", entropy),
    }).collect();

    let html = SecretsTmpl {
        current_route: "/secrets".into(),
        rows,
        pagination: pag,
        crate_name: f.crate_name.unwrap_or_default(),
        rule_id: f.rule_id.unwrap_or_default(),
        min_entropy: f.min_entropy.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ---- Typosquat ----

#[derive(Debug, Deserialize, Default)]
struct TypoFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    crate_name: Option<String>,
    crate_id: Option<String>,
    similar_crate_id: Option<String>,
    min_combined_score: Option<String>,
}
impl TypoFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

async fn typosquat_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<TypoFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let (crate_c, similar_c) = diesel::alias!(crates as crate_c, crates as similar_c);

    let mut query = typosquat_results::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(typosquat_results::crate_id)))
        .inner_join(similar_c.on(similar_c.field(crates::id).eq(typosquat_results::similar_crate_id)))
        .into_boxed();
    let mut cnt_q = typosquat_results::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(typosquat_results::crate_id)))
        .inner_join(similar_c.on(similar_c.field(crates::id).eq(typosquat_results::similar_crate_id)))
        .into_boxed();

    if let Some(ref s) = f.crate_id { if let Ok(v) = s.parse::<i64>() { query = query.filter(typosquat_results::crate_id.eq(v)); cnt_q = cnt_q.filter(typosquat_results::crate_id.eq(v)); } }
    if let Some(ref s) = f.similar_crate_id { if let Ok(v) = s.parse::<i64>() { query = query.filter(typosquat_results::similar_crate_id.eq(v)); cnt_q = cnt_q.filter(typosquat_results::similar_crate_id.eq(v)); } }
    if let Some(ref s) = f.min_combined_score { if let Ok(v) = s.parse::<i16>() { query = query.filter(typosquat_results::combined_score.ge(v)); cnt_q = cnt_q.filter(typosquat_results::combined_score.ge(v)); } }
    if let Some(ref s) = f.crate_name { let pat = format!("%{}%", s); query = query.filter(crate_c.field(crates::name).ilike(pat.clone())); cnt_q = cnt_q.filter(crate_c.field(crates::name).ilike(pat)); }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "crate_name" => if sort_desc { query.order(crate_c.field(crates::name).desc()) } else { query.order(crate_c.field(crates::name).asc()) },
        "similar_crate_name" => if sort_desc { query.order(similar_c.field(crates::name).desc()) } else { query.order(similar_c.field(crates::name).asc()) },
        "combined_score" => if sort_desc { query.order(typosquat_results::combined_score.desc()) } else { query.order(typosquat_results::combined_score.asc()) },
        "levenshtein" | "levenshtein_score" => if sort_desc { query.order(typosquat_results::levenshtein_score.desc()) } else { query.order(typosquat_results::levenshtein_score.asc()) },
        "jaro_winkler" | "jaro_winkler_score" => if sort_desc { query.order(typosquat_results::jaro_winkler_score.desc()) } else { query.order(typosquat_results::jaro_winkler_score.asc()) },
        "keyboard" | "keyboard_distance_score" => if sort_desc { query.order(typosquat_results::keyboard_distance_score.desc()) } else { query.order(typosquat_results::keyboard_distance_score.asc()) },
        "prefix" | "prefix_similarity_score" => if sort_desc { query.order(typosquat_results::prefix_similarity_score.desc()) } else { query.order(typosquat_results::prefix_similarity_score.asc()) },
        _ => if sort_desc { query.order(typosquat_results::id.desc()) } else { query.order(typosquat_results::id.asc()) },
    };

    type TR = (i64, i64, i64, i16, i16, i16, i16, i16, i16, String, String);
    let results: Vec<TR> = query
        .select((typosquat_results::id, typosquat_results::crate_id, typosquat_results::similar_crate_id,
            typosquat_results::levenshtein_score, typosquat_results::damerau_levenshtein_score,
            typosquat_results::jaro_winkler_score, typosquat_results::keyboard_distance_score,
            typosquat_results::prefix_similarity_score, typosquat_results::combined_score,
            crate_c.field(crates::name), similar_c.field(crates::name)))
        .limit(per_page).offset(offset).load(&mut conn).await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(ref x) = f.crate_name { if !x.is_empty() { params.push(("crate_name".into(), x.clone())); } }
    if let Some(ref x) = f.crate_id { if !x.is_empty() { params.push(("crate_id".into(), x.clone())); } }
    if let Some(ref x) = f.similar_crate_id { if !x.is_empty() { params.push(("similar_crate_id".into(), x.clone())); } }
    if let Some(ref x) = f.min_combined_score { if !x.is_empty() { params.push(("min_combined_score".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { params.push(("per_page".into(), x.clone())); } }
    let bqs = base_no_sort(&params);
    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let rows: Vec<TypoRow> = results.iter().map(|r| TypoRow {
        crate_name: r.9.clone(),
        crate_id: r.1.to_string(),
        similar_name: r.10.clone(),
        similar_id: r.2.to_string(),
        combined_bar: render_score_bar(r.8, 100),
        levenshtein: r.3.to_string(),
        jaro_winkler: r.5.to_string(),
        keyboard: r.6.to_string(),
        prefix: r.7.to_string(),
    }).collect();

    let html = TyposquatTmpl {
        current_route: "/typosquat".into(),
        rows,
        pagination: pag,
        crate_name: f.crate_name.unwrap_or_default(),
        min_combined_score: f.min_combined_score.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ---- Scan Results ----

#[derive(Debug, Deserialize, Default)]
struct ScanFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    crate_name: Option<String>,
    min_llm_score: Option<String>,
    max_llm_score: Option<String>,
    has_malicious_dependencies: Option<String>,
    has_executable_files: Option<String>,
    has_vulnerabilities: Option<String>,
    build_rs_network_calls: Option<String>,
    build_rs_process_spawning: Option<String>,
    build_rs_raw_ip: Option<String>,
}
impl ScanFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

async fn scan_results_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<ScanFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let mut query = scan_results::table
        .inner_join(crates::table.on(crates::id.eq(scan_results::id)))
        .into_boxed();
    let mut cnt_q = scan_results::table
        .inner_join(crates::table.on(crates::id.eq(scan_results::id)))
        .into_boxed();

    if let Some(ref s) = f.has_malicious_dependencies { if let Some(v) = parse_opt_bool(s) { query = query.filter(scan_results::has_malicious_dependencies.eq(v)); cnt_q = cnt_q.filter(scan_results::has_malicious_dependencies.eq(v)); } }
    if let Some(ref s) = f.min_llm_score { if let Some(v) = parse_opt_i16(s) { query = query.filter(scan_results::llm_malicious_score.ge(v)); cnt_q = cnt_q.filter(scan_results::llm_malicious_score.ge(v)); } }
    if let Some(ref s) = f.max_llm_score { if let Some(v) = parse_opt_i16(s) { query = query.filter(scan_results::llm_malicious_score.le(v)); cnt_q = cnt_q.filter(scan_results::llm_malicious_score.le(v)); } }
    if let Some(ref s) = f.has_executable_files { if let Some(v) = parse_opt_bool(s) { query = query.filter(scan_results::has_executable_files.eq(v)); cnt_q = cnt_q.filter(scan_results::has_executable_files.eq(v)); } }
    if let Some(ref s) = f.has_vulnerabilities { if let Some(v) = parse_opt_bool(s) { if v { query = query.filter(scan_results::cargo_audit_vulns_count.gt(0i16)); cnt_q = cnt_q.filter(scan_results::cargo_audit_vulns_count.gt(0i16)); } else { query = query.filter(scan_results::cargo_audit_vulns_count.eq(0i16)); cnt_q = cnt_q.filter(scan_results::cargo_audit_vulns_count.eq(0i16)); } } }
    if let Some(ref s) = f.build_rs_network_calls { if let Some(v) = parse_opt_bool(s) { query = query.filter(scan_results::build_rs_network_calls.eq(v)); cnt_q = cnt_q.filter(scan_results::build_rs_network_calls.eq(v)); } }
    if let Some(ref s) = f.build_rs_process_spawning { if let Some(v) = parse_opt_bool(s) { query = query.filter(scan_results::build_rs_has_process_spawning.eq(v)); cnt_q = cnt_q.filter(scan_results::build_rs_has_process_spawning.eq(v)); } }
    if let Some(ref s) = f.build_rs_raw_ip { if let Some(v) = parse_opt_bool(s) { query = query.filter(scan_results::build_rs_has_raw_ip.eq(v)); cnt_q = cnt_q.filter(scan_results::build_rs_has_raw_ip.eq(v)); } }
    if let Some(ref s) = f.crate_name { let pat = format!("%{}%", s); query = query.filter(crates::name.ilike(pat.clone())); cnt_q = cnt_q.filter(crates::name.ilike(pat)); }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "crate_name" => if sort_desc { query.order(crates::name.desc()) } else { query.order(crates::name.asc()) },
        "llm_score" | "llm_malicious_score" => if sort_desc { query.order(scan_results::llm_malicious_score.desc()) } else { query.order(scan_results::llm_malicious_score.asc()) },
        "vulns" | "vulns_count" => if sort_desc { query.order(scan_results::cargo_audit_vulns_count.desc()) } else { query.order(scan_results::cargo_audit_vulns_count.asc()) },
        "malicious" => if sort_desc { query.order(scan_results::has_malicious_dependencies.desc()) } else { query.order(scan_results::has_malicious_dependencies.asc()) },
        "network" => if sort_desc { query.order(scan_results::build_rs_network_calls.desc()) } else { query.order(scan_results::build_rs_network_calls.asc()) },
        "process" => if sort_desc { query.order(scan_results::build_rs_has_process_spawning.desc()) } else { query.order(scan_results::build_rs_has_process_spawning.asc()) },
        _ => if sort_desc { query.order(scan_results::id.desc()) } else { query.order(scan_results::id.asc()) },
    };

    type SR = (i64, String, bool, i16, String, bool, i16, i16, bool, bool, f32, bool, bool, bool);
    let results: Vec<SR> = query
        .select((scan_results::id, crates::name, scan_results::has_malicious_dependencies,
            scan_results::llm_malicious_score, scan_results::llm_notes, scan_results::has_executable_files,
            scan_results::cargo_audit_max_dep_score, scan_results::cargo_audit_vulns_count,
            scan_results::build_rs_network_calls, scan_results::build_rs_has_link_directive,
            scan_results::build_rs_entropy_score, scan_results::build_rs_has_process_spawning,
            scan_results::build_rs_has_raw_ip, scan_results::build_rs_has_free_tlds))
        .limit(per_page).offset(offset).load(&mut conn).await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(ref x) = f.crate_name { if !x.is_empty() { params.push(("crate_name".into(), x.clone())); } }
    if let Some(ref x) = f.min_llm_score { if !x.is_empty() { params.push(("min_llm_score".into(), x.clone())); } }
    if let Some(ref x) = f.max_llm_score { if !x.is_empty() { params.push(("max_llm_score".into(), x.clone())); } }
    if let Some(ref x) = f.has_malicious_dependencies { if !x.is_empty() { params.push(("has_malicious_dependencies".into(), x.clone())); } }
    if let Some(ref x) = f.has_executable_files { if !x.is_empty() { params.push(("has_executable_files".into(), x.clone())); } }
    if let Some(ref x) = f.has_vulnerabilities { if !x.is_empty() { params.push(("has_vulnerabilities".into(), x.clone())); } }
    if let Some(ref x) = f.build_rs_network_calls { if !x.is_empty() { params.push(("build_rs_network_calls".into(), x.clone())); } }
    if let Some(ref x) = f.build_rs_process_spawning { if !x.is_empty() { params.push(("build_rs_process_spawning".into(), x.clone())); } }
    if let Some(ref x) = f.build_rs_raw_ip { if !x.is_empty() { params.push(("build_rs_raw_ip".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { params.push(("per_page".into(), x.clone())); } }
    let bqs = base_no_sort(&params);
    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let rows: Vec<ScanRow> = results.iter().map(|r| ScanRow {
        id: r.0.to_string(),
        crate_name: r.1.clone(),
        risk_bar: render_score_bar(r.3, 100),
        risk_badge: render_risk_badge(r.3),
        malicious_deps_badge: render_bool_badge(r.2),
        vulns_badge: if r.7 > 0 { format!("<span class=\"badge badge-yes\">{}</span>", r.7) } else { "<span class=\"badge badge-no\">0</span>".into() },
        network_badge: render_bool_badge(r.8),
        process_badge: render_bool_badge(r.11),
        executables_badge: render_bool_badge(r.5),
    }).collect();

    let html = ScanResultsTmpl {
        current_route: "/scan-results".into(),
        rows,
        pagination: pag,
        crate_name: f.crate_name.unwrap_or_default(),
        min_llm_score: f.min_llm_score.unwrap_or_default(),
        max_llm_score: f.max_llm_score.unwrap_or_default(),
        has_malicious: f.has_malicious_dependencies.unwrap_or_default(),
        has_vulns: f.has_vulnerabilities.unwrap_or_default(),
        build_net: f.build_rs_network_calls.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ---- Scan Result Detail (JSON for modal) ----

#[derive(serde::Serialize)]
struct ScanDetail {
    id: i64,
    crate_name: String,
    has_malicious_dependencies: bool,
    llm_malicious_score: i16,
    llm_notes: String,
    has_executable_files: bool,
    cargo_audit_max_dep_score: i16,
    cargo_audit_vulns_count: i16,
    build_rs_network_calls: bool,
    build_rs_has_link_directive: bool,
    build_rs_entropy_score: f32,
    build_rs_has_process_spawning: bool,
    build_rs_has_raw_ip: bool,
    build_rs_has_free_tlds: bool,
}

async fn scan_result_detail(
    State(pool): State<Arc<DbPool>>,
    Path(id): Path<i64>,
) -> Result<Json<ScanDetail>, AppError> {
    let mut conn = pool.get().await?;
    type SR = (i64, String, bool, i16, String, bool, i16, i16, bool, bool, f32, bool, bool, bool);
    let r: SR = scan_results::table
        .inner_join(crates::table.on(crates::id.eq(scan_results::id)))
        .filter(scan_results::id.eq(id))
        .select((scan_results::id, crates::name, scan_results::has_malicious_dependencies,
            scan_results::llm_malicious_score, scan_results::llm_notes, scan_results::has_executable_files,
            scan_results::cargo_audit_max_dep_score, scan_results::cargo_audit_vulns_count,
            scan_results::build_rs_network_calls, scan_results::build_rs_has_link_directive,
            scan_results::build_rs_entropy_score, scan_results::build_rs_has_process_spawning,
            scan_results::build_rs_has_raw_ip, scan_results::build_rs_has_free_tlds))
        .first(&mut conn).await?;

    Ok(Json(ScanDetail {
        id: r.0, crate_name: r.1, has_malicious_dependencies: r.2, llm_malicious_score: r.3,
        llm_notes: r.4, has_executable_files: r.5, cargo_audit_max_dep_score: r.6,
        cargo_audit_vulns_count: r.7, build_rs_network_calls: r.8, build_rs_has_link_directive: r.9,
        build_rs_entropy_score: r.10, build_rs_has_process_spawning: r.11, build_rs_has_raw_ip: r.12,
        build_rs_has_free_tlds: r.13,
    }))
}

// ---- Metrics ----

#[derive(Debug, Deserialize, Default)]
struct MetricFilters {
    page: Option<String>,
    per_page: Option<String>,
    sort_by: Option<String>,
    sort_desc: Option<String>,
    crate_name: Option<String>,
    crate_id: Option<String>,
}
impl MetricFilters {
    fn page(&self) -> i64 { self.page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PAGE).max(1) }
    fn per_page(&self) -> i64 { self.per_page.as_deref().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PER_PAGE).clamp(1, 100) }
    fn sort_by(&self) -> String { self.sort_by.clone().unwrap_or_default() }
    fn sort_desc(&self) -> bool { matches!(self.sort_desc.as_deref(), Some("1") | Some("true")) }
}

async fn metrics_list(
    State(pool): State<Arc<DbPool>>,
    Query(f): Query<MetricFilters>,
) -> Result<Html<String>, AppError> {
    let mut conn = pool.get().await?;
    let page = f.page();
    let per_page = f.per_page();
    let offset = (page - 1) * per_page;
    let sort_desc = f.sort_desc();
    let sort_by = f.sort_by();

    let mut query = analysis_metrics::table
        .inner_join(crates::table.on(crates::id.eq(analysis_metrics::crate_id)))
        .into_boxed();
    let mut cnt_q = analysis_metrics::table
        .inner_join(crates::table.on(crates::id.eq(analysis_metrics::crate_id)))
        .into_boxed();

    if let Some(ref s) = f.crate_id { if let Ok(v) = s.parse::<i64>() { query = query.filter(analysis_metrics::crate_id.eq(v)); cnt_q = cnt_q.filter(analysis_metrics::crate_id.eq(v)); } }
    if let Some(ref s) = f.crate_name { let pat = format!("%{}%", s); query = query.filter(crates::name.ilike(pat.clone())); cnt_q = cnt_q.filter(crates::name.ilike(pat)); }

    let total: i64 = cnt_q.select(count_star()).first(&mut conn).await?;

    query = match sort_by.as_str() {
        "crate_name" => if sort_desc { query.order(crates::name.desc()) } else { query.order(crates::name.asc()) },
        "total_duration" | "total_duration_ms" => if sort_desc { query.order(analysis_metrics::total_duration_ms.desc()) } else { query.order(analysis_metrics::total_duration_ms.asc()) },
        "completed_at" => if sort_desc { query.order(analysis_metrics::completed_at.desc()) } else { query.order(analysis_metrics::completed_at.asc()) },
        _ => if sort_desc { query.order(analysis_metrics::completed_at.desc()) } else { query.order(analysis_metrics::completed_at.asc()) },
    };

    type MR = (Uuid, i64, String, i64, Option<i64>, Option<i64>, Option<i64>, Option<i64>, Option<i64>, Option<i64>, Option<String>, NaiveDateTime, NaiveDateTime);
    let results: Vec<MR> = query
        .select((analysis_metrics::id, analysis_metrics::crate_id, crates::name,
            analysis_metrics::total_duration_ms, analysis_metrics::cargo_audit_duration_ms,
            analysis_metrics::gitleaks_duration_ms, analysis_metrics::executable_check_duration_ms,
            analysis_metrics::build_rs_analysis_duration_ms, analysis_metrics::llm_analysis_duration_ms,
            analysis_metrics::download_duration_ms, analysis_metrics::worker_id,
            analysis_metrics::started_at, analysis_metrics::completed_at))
        .limit(per_page).offset(offset).load(&mut conn).await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as i64;

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(ref x) = f.crate_name { if !x.is_empty() { params.push(("crate_name".into(), x.clone())); } }
    if let Some(ref x) = f.crate_id { if !x.is_empty() { params.push(("crate_id".into(), x.clone())); } }
    if let Some(ref x) = f.per_page { if *x != DEFAULT_PER_PAGE.to_string() { params.push(("per_page".into(), x.clone())); } }
    let bqs = base_no_sort(&params);
    let pag = PaginationHtml::render(page, total_pages, total, per_page, &bqs, &sort_by, sort_desc);

    let rows: Vec<MetricRow> = results.iter().map(|r| MetricRow {
        crate_id: r.1.to_string(),
        crate_name: r.2.clone(),
        total_ms: r.3.to_string(),
        download_ms: fmt_opt_dur(r.9),
        cargo_audit_ms: fmt_opt_dur(r.4),
        gitleaks_ms: fmt_opt_dur(r.5),
        executables_ms: fmt_opt_dur(r.6),
        build_rs_ms: fmt_opt_dur(r.7),
        llm_ms: fmt_opt_dur(r.8),
        worker_id: r.10.clone().unwrap_or_default(),
        completed_at: r.12.format("%Y-%m-%d %H:%M").to_string(),
    }).collect();

    let html = MetricsTmpl {
        current_route: "/metrics".into(),
        rows,
        pagination: pag,
        crate_name: f.crate_name.unwrap_or_default(),
        crate_id: f.crate_id.unwrap_or_default(),
        sort_by,
        sort_desc,
        per_page: per_page.to_string(),
        base_query_no_sort: bqs,
    }.render_once()?;
    Ok(Html(html))
}

// ====== MAIN ======

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "webpanel_sailfish=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_file("config.toml")
        .or_else(|_| Config::from_file("webpanel-sailfish/config.toml"))
        .expect("Failed to load config.toml");

    tracing::info!("Starting on {}:{}", config.server_host, config.server_port);

    let pool = create_pool(&config.connection_string, config.max_connections).await?;
    let pool = Arc::new(pool);

    let app = Router::new()
        // HTML pages (server-rendered)
        .route("/", get(dashboard))
        .route("/crates", get(crates_list))
        .route("/dependencies", get(deps_list))
        .route("/vulnerabilities", get(vulns_list))
        .route("/secrets", get(secrets_list))
        .route("/typosquat", get(typosquat_list))
        .route("/scan-results", get(scan_results_list))
        .route("/metrics", get(metrics_list))
        // JSON API (for modals)
        .route("/api/scan-results/{id}", get(scan_result_detail))
        // Static files
        .nest_service("/static", ServeDir::new(concat!(env!("CARGO_MANIFEST_DIR"), "/static")))
        .with_state(pool)
        .layer(CorsLayer::permissive());

    let addr = format!("{}:{}", config.server_host, config.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

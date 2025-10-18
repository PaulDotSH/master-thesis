use tokio::process::Command;
use sonic_rs::JsonValueTrait;

pub async fn run_cargo_audit(crate_dir: &str, _crate_id: i64) -> Result<Vec<(String, u8)>, anyhow::Error> {
    let stdout = Command::new("cargo")
        .arg("audit")
        .arg("--json")
        .current_dir(crate_dir)
        .output()
        .await?;
    
    // Using sonic_rs for speed
    let stdout = String::from_utf8(stdout.stdout)?;

    let json: sonic_rs::Value = sonic_rs::from_str(&stdout)?;
    
    let mut vulnerabilities = Vec::new();
    
    let list = &json["vulnerabilities"]["list"];
    if list.is_array() {
        let mut i = 0;
        while !list[i].is_null() {
            let vuln = &list[i];
            
            // Get the advisory ID
            if vuln["advisory"]["id"].is_str() {
                let id = vuln["advisory"]["id"].as_str().unwrap();
                // Remove "RUSTSEC-" prefix
                let clean_id = id.strip_prefix("RUSTSEC-").unwrap_or(id).to_string();
                
                // Parse CVSS score from the cvss field if available
                let severity_score = if vuln["advisory"]["cvss"].is_str() {
                    let cvss_str = vuln["advisory"]["cvss"].as_str().unwrap();
                    parse_cvss_base_score(cvss_str)
                } else {
                    0u8
                };
                
                vulnerabilities.push((clean_id, severity_score));
            }
            
            i += 1;
        }
    }
    
    Ok(vulnerabilities)
}

/// Parse CVSS base score from a CVSS vector string
fn parse_cvss_base_score(cvss_str: &str) -> u8 {
    // TODO: Change to cvssrust
    
    let metrics: std::collections::HashMap<&str, &str> = cvss_str
        .split('/')
        .skip(1) // Skip the "CVSS:3.1" part
        .filter_map(|part| {
            let mut split = part.split(':');
            Some((split.next()?, split.next()?))
        })
        .collect();
    
    let confidentiality = match metrics.get("C") {
        Some(&"H") => 0.56,
        Some(&"L") => 0.22,
        _ => 0.0, // None
    };
    
    let integrity = match metrics.get("I") {
        Some(&"H") => 0.56,
        Some(&"L") => 0.22,
        _ => 0.0, // None
    };
    
    let availability = match metrics.get("A") {
        Some(&"H") => 0.56,
        Some(&"L") => 0.22,
        _ => 0.0, // None
    };
    
    let scope_changed = matches!(metrics.get("S"), Some(&"C"));
    
    let impact_base: f64 = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability));
    let impact: f64 = if scope_changed {
        7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02).powi(15)
    } else {
        6.42 * impact_base
    };
    
    if impact <= 0.0 {
        return 0;
    }
    
    let attack_vector: f64 = match metrics.get("AV") {
        Some(&"N") => 0.85,
        Some(&"A") => 0.62,
        Some(&"L") => 0.55,
        Some(&"P") => 0.2,
        _ => 0.85,
    };
    
    let attack_complexity: f64 = match metrics.get("AC") {
        Some(&"L") => 0.77,
        Some(&"H") => 0.44,
        _ => 0.77,
    };
    
    let privileges_required: f64 = if scope_changed {
        match metrics.get("PR") {
            Some(&"N") => 0.85,
            Some(&"L") => 0.68,
            Some(&"H") => 0.50,
            _ => 0.85,
        }
    } else {
        match metrics.get("PR") {
            Some(&"N") => 0.85,
            Some(&"L") => 0.62,
            Some(&"H") => 0.27,
            _ => 0.85,
        }
    };
    
    let user_interaction: f64 = match metrics.get("UI") {
        Some(&"N") => 0.85,
        Some(&"R") => 0.62,
        _ => 0.85,
    };
    
    let exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    
    let base_score: f64 = if scope_changed {
        let score: f64 = 1.08 * (impact + exploitability);
        score.min(10.0)
    } else {
        let score: f64 = impact + exploitability;
        score.min(10.0)
    };
    
    (base_score * 10.0).ceil() as u8
}
use crate::error::Result;
use regex::Regex;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub product: String,
    pub version_range: String,
    pub cve_id: String,
    pub cvss: Option<f32>,
    pub summary: String,
    pub references: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub struct CveDatabase {
    pub entries: Vec<CveEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub cvss: Option<f32>,
    pub summary: String,
    pub references: Vec<String>,
    pub remediation: String,
}

impl CveDatabase {
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let entries = serde_json::from_str::<Vec<CveEntry>>(&data)?;
        Ok(Self { entries })
    }

    pub fn match_service(&self, product: &str, version: Option<&str>) -> Vec<CveMatch> {
        self.entries
            .iter()
            .filter(|e| e.product.eq_ignore_ascii_case(product))
            .filter(|e| version.is_some_and(|v| version_in_range(v, &e.version_range)))
            .map(|e| CveMatch {
                cve_id: e.cve_id.clone(),
                cvss: e.cvss,
                summary: e.summary.clone(),
                references: e.references.clone(),
                remediation: e.remediation.clone(),
            })
            .collect()
    }
}

pub fn version_in_range(version: &str, range: &str) -> bool {
    if looks_like_semver(version) && range.contains(',') {
        return semver_match(version, range);
    }
    simple_compare_match(version, range)
}

fn looks_like_semver(version: &str) -> bool {
    Version::parse(normalize_semver(version).as_str()).is_ok()
}

fn normalize_semver(v: &str) -> String {
    let mut parts: Vec<&str> = v.trim_start_matches('v').split('.').collect();
    while parts.len() < 3 {
        parts.push("0");
    }
    parts[..3].join(".")
}

fn semver_match(version: &str, range: &str) -> bool {
    let version = match Version::parse(&normalize_semver(version)) {
        Ok(v) => v,
        Err(_) => return false,
    };

    for cond in range.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (op, raw) = split_op(cond);
        let other = match Version::parse(&normalize_semver(raw)) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let ok = match op {
            "<" => version < other,
            "<=" => version <= other,
            ">" => version > other,
            ">=" => version >= other,
            "=" | "==" => version == other,
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn simple_compare_match(version: &str, range: &str) -> bool {
    if range.trim().eq_ignore_ascii_case("any") {
        return true;
    }
    let re = Regex::new(r"^(<=|>=|<|>|==|=)?\s*(.+)$").expect("regex");
    for cond in range.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some(caps) = re.captures(cond) else {
            return false;
        };
        let op = caps.get(1).map(|m| m.as_str()).unwrap_or("=");
        let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let cmp = lexical_compare(version, rhs);
        let ok = match op {
            "<" => cmp.is_lt(),
            "<=" => cmp.is_le(),
            ">" => cmp.is_gt(),
            ">=" => cmp.is_ge(),
            "=" | "==" => cmp.is_eq(),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn lexical_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let split = |s: &str| {
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|x| !x.is_empty())
            .map(|p| p.to_ascii_lowercase())
            .collect::<Vec<String>>()
    };
    split(a).cmp(&split(b))
}

fn split_op(input: &str) -> (&str, &str) {
    ["<=", ">=", "<", ">", "==", "="]
        .iter()
        .find_map(|op| input.strip_prefix(op).map(|rest| (*op, rest.trim())))
        .unwrap_or(("=", input.trim()))
}

#[cfg(test)]
mod tests {
    use super::version_in_range;

    #[test]
    fn semver_range_matching() {
        assert!(version_in_range("8.9.1", ">=8.0.0,<9.0.0"));
        assert!(!version_in_range("9.1.0", ">=8.0.0,<9.0.0"));
    }

    #[test]
    fn simple_matching_fallback() {
        assert!(version_in_range("OpenSSH_7.2", "<=OpenSSH_7.5"));
    }
}

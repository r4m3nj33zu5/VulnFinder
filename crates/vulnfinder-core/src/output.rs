use crate::cve_db::CveMatch;
use crate::scanner::HostScanResult;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub hosts: Vec<HostReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostReport {
    pub target: String,
    pub ports: Vec<PortReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub evidence: Vec<String>,
    pub cves: Vec<CveMatch>,
}

pub fn build_report(
    results: &[HostScanResult],
    matcher: impl Fn(&str, Option<&str>) -> Vec<CveMatch>,
) -> ScanReport {
    let hosts = results
        .iter()
        .map(|host| HostReport {
            target: host.target.clone(),
            ports: host
                .ports
                .iter()
                .filter(|p| p.open)
                .map(|p| {
                    let (service, product, version, evidence) = if let Some(fp) = &p.fingerprint {
                        (
                            Some(fp.service.clone()),
                            fp.product.clone(),
                            fp.version.clone(),
                            fp.evidence.clone(),
                        )
                    } else {
                        (None, None, None, Vec::new())
                    };

                    let cves = product
                        .as_deref()
                        .map(|prod| matcher(prod, version.as_deref()))
                        .unwrap_or_default();

                    PortReport {
                        port: p.port,
                        service,
                        product,
                        version,
                        evidence,
                        cves,
                    }
                })
                .collect(),
        })
        .collect();

    ScanReport { hosts }
}

pub fn render_table(report: &ScanReport, show_evidence: bool) -> String {
    let mut out = String::new();
    out.push_str("TARGET            PORT   SERVICE  PRODUCT         VERSION   CVES\n");
    out.push_str("-------------------------------------------------------------------\n");

    for host in &report.hosts {
        for p in &host.ports {
            out.push_str(&format!(
                "{:<17} {:<6} {:<8} {:<15} {:<8} {:<3}\n",
                host.target,
                p.port,
                p.service.clone().unwrap_or_else(|| "-".into()),
                p.product.clone().unwrap_or_else(|| "-".into()),
                p.version.clone().unwrap_or_else(|| "-".into()),
                p.cves.len()
            ));

            for cve in &p.cves {
                out.push_str(&format!(
                    "  - {} CVSS:{:?} {}\n",
                    cve.cve_id, cve.cvss, cve.summary
                ));
                out.push_str(&format!("    Remediation: {}\n", cve.remediation));
                if !cve.references.is_empty() {
                    out.push_str(&format!("    References: {}\n", cve.references.join(", ")));
                }
            }

            if show_evidence && !p.evidence.is_empty() {
                out.push_str(&format!("    Evidence: {}\n", p.evidence.join(" | ")));
            }
        }
    }

    out
}

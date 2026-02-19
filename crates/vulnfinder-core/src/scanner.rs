use crate::fingerprint::{fingerprint_service, ServiceFingerprint};
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub timeout_ms: u64,
    pub concurrency: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanStats {
    pub total_targets: usize,
    pub total_ports: usize,
    pub scanned: usize,
    pub open_ports: usize,
    pub services_identified: usize,
    pub cves_matched: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    pub fingerprint: Option<ServiceFingerprint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostScanResult {
    pub target: String,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub message: String,
    pub current_target: String,
    pub current_port: u16,
    pub stats: ScanStats,
}

pub async fn scan_targets(
    targets: Vec<String>,
    ports: Vec<u16>,
    config: ScanConfig,
    events: Option<mpsc::UnboundedSender<ScanEvent>>,
) -> Vec<HostScanResult> {
    let stats = Arc::new(Mutex::new(ScanStats {
        total_targets: targets.len(),
        total_ports: targets.len() * ports.len(),
        ..Default::default()
    }));

    let jobs: Vec<(String, u16)> = targets
        .iter()
        .flat_map(|t| ports.iter().map(|p| (t.clone(), *p)))
        .collect();

    let results = stream::iter(jobs)
        .map(|(target, port)| {
            let stats = Arc::clone(&stats);
            let events = events.clone();
            let config = config.clone();
            async move {
                let open = is_port_open(&target, port, config.timeout_ms).await;
                let fingerprint = if open {
                    fingerprint_service(&target, port, config.timeout_ms).await
                } else {
                    None
                };

                {
                    let mut st = stats.lock().await;
                    st.scanned += 1;
                    if open {
                        st.open_ports += 1;
                    }
                    if fingerprint.is_some() {
                        st.services_identified += 1;
                    }
                    if let Some(tx) = &events {
                        let _ = tx.send(ScanEvent {
                            message: if open {
                                format!("open {target}:{port}")
                            } else {
                                format!("closed {target}:{port}")
                            },
                            current_target: target.clone(),
                            current_port: port,
                            stats: st.clone(),
                        });
                    }
                }

                (
                    target,
                    PortResult {
                        port,
                        open,
                        fingerprint,
                    },
                )
            }
        })
        .buffer_unordered(config.concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut by_host = std::collections::BTreeMap::<String, Vec<PortResult>>::new();
    for (target, port_result) in results {
        by_host.entry(target).or_default().push(port_result);
    }

    by_host
        .into_iter()
        .map(|(target, mut ports)| {
            ports.sort_by_key(|p| p.port);
            HostScanResult { target, ports }
        })
        .collect()
}

async fn is_port_open(target: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{target}:{port}");
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .map(|res| res.is_ok())
        .unwrap_or(false)
}

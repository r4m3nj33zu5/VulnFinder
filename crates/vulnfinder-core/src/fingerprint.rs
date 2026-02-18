use serde::Serialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_EVIDENCE: usize = 200;

#[derive(Debug, Clone, Serialize)]
pub struct ServiceFingerprint {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub evidence: Vec<String>,
}

pub async fn fingerprint_service(
    target: &str,
    port: u16,
    timeout_ms: u64,
) -> Option<ServiceFingerprint> {
    if let Some(ssh) = ssh_fingerprint(target, port, timeout_ms).await {
        return Some(ssh);
    }

    if port == 80 || port == 8080 {
        return http_fingerprint(target, port, timeout_ms).await;
    }

    if port == 443 {
        if let Some(fp) = tls_fingerprint(target, port, timeout_ms).await {
            return Some(fp);
        }
        return http_fingerprint(target, port, timeout_ms).await;
    }

    let mut evidence = Vec::new();
    if let Some(line) = banner_probe(target, port, timeout_ms).await {
        evidence.push(format!("banner: {}", truncate(&line)));
    }

    Some(ServiceFingerprint {
        service: "tcp".to_string(),
        product: None,
        version: None,
        evidence,
    })
}

async fn banner_probe(target: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{target}:{port}");
    let fut = async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.ok()?;
        Some(String::from_utf8_lossy(&buf[..n]).replace(['\r', '\n'], " "))
    };
    timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()
        .flatten()
}

async fn ssh_fingerprint(target: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
    let banner = banner_probe(target, port, timeout_ms).await?;
    let banner_trimmed = banner.trim();
    if !banner_trimmed.starts_with("SSH-") {
        return None;
    }
    let version = banner_trimmed
        .split('-')
        .nth(2)
        .map(|v| v.split_whitespace().next().unwrap_or(v).to_string());

    Some(ServiceFingerprint {
        service: "ssh".to_string(),
        product: Some("OpenSSH".to_string()),
        version,
        evidence: vec![format!("ssh banner: {}", truncate(banner_trimmed))],
    })
}

async fn http_fingerprint(target: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
    let addr = format!("{target}:{port}");
    let fut = async {
        let mut stream = TcpStream::connect(&addr).await.ok()?;
        let req = format!(
            "HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: vulnfinder\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.ok()?;
        let response = String::from_utf8_lossy(&buf[..n]).to_string();
        parse_http_response(&response)
    };

    timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()
        .flatten()
}

fn parse_http_response(response: &str) -> Option<ServiceFingerprint> {
    let mut server_header = None;
    for line in response.lines() {
        if line.to_ascii_lowercase().starts_with("server:") {
            server_header = Some(line.trim().to_string());
            break;
        }
    }

    let (product, version) = if let Some(server) = &server_header {
        parse_product_version(server.split(':').nth(1).unwrap_or_default().trim())
    } else {
        (None, None)
    };

    Some(ServiceFingerprint {
        service: "http".to_string(),
        product,
        version,
        evidence: vec![format!(
            "http server header: {}",
            truncate(server_header.as_deref().unwrap_or("none"))
        )],
    })
}

async fn tls_fingerprint(target: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
    let addr = format!("{target}:{port}");
    let target_host = target.to_string();
    let fut = async move {
        let stream = TcpStream::connect(addr).await.ok()?;
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .ok()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let tls_stream = connector.connect(&target_host, stream).await.ok()?;
        let cert = tls_stream.get_ref().peer_certificate().ok().flatten();

        let mut evidence = Vec::new();
        if let Some(cert) = cert {
            if let Ok(der) = cert.to_der() {
                if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) {
                    evidence.push(format!(
                        "tls cert subject: {}",
                        truncate(&parsed.subject().to_string())
                    ));
                    evidence.push(format!(
                        "tls cert issuer: {}",
                        truncate(&parsed.issuer().to_string())
                    ));
                }
            }
            if evidence.is_empty() {
                evidence.push("tls cert: parsed fields unavailable".to_string());
            }
        } else {
            evidence.push("tls cert: unavailable".to_string());
        }

        Some(ServiceFingerprint {
            service: "tls".to_string(),
            product: None,
            version: None,
            evidence,
        })
    };

    timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()
        .flatten()
}

fn parse_product_version(raw: &str) -> (Option<String>, Option<String>) {
    if raw.is_empty() {
        return (None, None);
    }
    if let Some((product, version)) = raw.split_once('/') {
        return (
            Some(product.trim().to_string()),
            Some(version.trim().to_string()),
        );
    }
    (Some(raw.to_string()), None)
}

fn truncate(value: &str) -> String {
    value.chars().take(MAX_EVIDENCE).collect()
}

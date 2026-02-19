use crate::error::{Result, VulnFinderError};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

const MAX_EXPANDED_TARGETS: usize = 4096;

pub fn parse_targets(input: &str) -> Result<Vec<String>> {
    if let Ok(ip) = IpAddr::from_str(input) {
        return Ok(vec![ip.to_string()]);
    }

    if let Ok(net) = IpNet::from_str(input) {
        let mut out = Vec::new();
        for ip in net.hosts() {
            out.push(ip.to_string());
            if out.len() > MAX_EXPANDED_TARGETS {
                return Err(VulnFinderError::InvalidTarget(format!(
                    "CIDR expands beyond {MAX_EXPANDED_TARGETS} hosts"
                )));
            }
        }
        return Ok(out);
    }

    if let Some((start, end)) = input.split_once('-') {
        let start = IpAddr::from_str(start.trim())
            .map_err(|_| VulnFinderError::InvalidTarget(input.to_string()))?;
        let end = IpAddr::from_str(end.trim())
            .map_err(|_| VulnFinderError::InvalidTarget(input.to_string()))?;

        return expand_ip_range(start, end);
    }

    if is_valid_hostname(input) {
        return Ok(vec![input.to_string()]);
    }

    Err(VulnFinderError::InvalidTarget(input.to_string()))
}

fn expand_ip_range(start: IpAddr, end: IpAddr) -> Result<Vec<String>> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            let s = u32::from(s);
            let e = u32::from(e);
            if s > e {
                return Err(VulnFinderError::InvalidTarget(
                    "range start must be <= range end".to_string(),
                ));
            }
            let mut out = Vec::new();
            for value in s..=e {
                out.push(std::net::Ipv4Addr::from(value).to_string());
                if out.len() > MAX_EXPANDED_TARGETS {
                    return Err(VulnFinderError::InvalidTarget(format!(
                        "range expands beyond {MAX_EXPANDED_TARGETS} hosts"
                    )));
                }
            }
            Ok(out)
        }
        _ => Err(VulnFinderError::InvalidTarget(
            "IP ranges currently support IPv4 only".to_string(),
        )),
    }
}

fn is_valid_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::parse_targets;

    #[test]
    fn parses_single_ip() {
        let t = parse_targets("127.0.0.1").unwrap();
        assert_eq!(t, vec!["127.0.0.1"]);
    }

    #[test]
    fn parses_cidr() {
        let t = parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(t, vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn parses_range() {
        let t = parse_targets("10.0.0.1-10.0.0.3").unwrap();
        assert_eq!(t.len(), 3);
    }
}

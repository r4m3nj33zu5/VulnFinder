use crate::error::{Result, VulnFinderError};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const DEFAULT_PORTS: &[u16] = &[22, 53, 80, 443, 445, 3389];

pub fn load_ports(ports: Option<&str>, ports_file: Option<&Path>) -> Result<Vec<u16>> {
    let mut values = BTreeSet::new();

    if let Some(raw) = ports {
        for part in raw.split(',') {
            if part.trim().is_empty() {
                continue;
            }
            let parsed = parse_port(part.trim())?;
            values.insert(parsed);
        }
    }

    if let Some(path) = ports_file {
        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            values.insert(parse_port(line)?);
        }
    }

    if values.is_empty() {
        values.extend(DEFAULT_PORTS);
    }

    Ok(values.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| VulnFinderError::InvalidPort(value.to_string()))?;
    if port == 0 {
        return Err(VulnFinderError::InvalidPort(value.to_string()));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::{load_ports, DEFAULT_PORTS};
    use std::fs;

    #[test]
    fn defaults_when_no_inputs() {
        let ports = load_ports(None, None).unwrap();
        assert_eq!(ports, DEFAULT_PORTS);
    }

    #[test]
    fn merges_sources() {
        let path = std::env::temp_dir().join("vulnfinder_ports_test.txt");
        fs::write(&path, "443\n8080\n").unwrap();
        let ports = load_ports(Some("22,80"), Some(path.as_path())).unwrap();
        assert_eq!(ports, vec![22, 80, 443, 8080]);
        let _ = fs::remove_file(path);
    }
}

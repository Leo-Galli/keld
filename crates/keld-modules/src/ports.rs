//! Port list parsing: single ports, lists, ranges, and top-N presets.

use thiserror::Error;

/// nmap-style top 100 TCP ports (common services).
pub const TOP_100: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
    144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];

/// Top 1000: well-known low ports plus TOP_100 extras above 1024.
pub fn top_1000() -> Vec<u16> {
    let mut ports: Vec<u16> = (1u16..=1024).collect();
    for &p in TOP_100 {
        if p > 1024 {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports.truncate(1000);
    ports
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortParseError {
    #[error("empty port specification")]
    Empty,
    #[error("invalid port `{token}`: {reason}")]
    Invalid { token: String, reason: String },
    #[error("port range `{spec}` is empty or inverted")]
    BadRange { spec: String },
    #[error("too many ports ({count}); max is {max}")]
    TooMany { count: usize, max: usize },
}

/// Maximum ports accepted in one scan job.
pub const MAX_PORTS: usize = 10_000;

/// Parse a ports string into a deduplicated, sorted list.
///
/// Accepts: `22`, `80,443`, `1-1024`, `top`, `top100`, `top-100`, `top1000`, `top-ports`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, PortParseError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(PortParseError::Empty);
    }

    let lower = spec.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "top" | "top100" | "top-100" | "top-ports" | "topports"
    ) {
        return Ok(TOP_100.to_vec());
    }
    if matches!(lower.as_str(), "top1000" | "top-1000") {
        return Ok(top_1000());
    }

    let mut ports = Vec::new();
    for raw in spec.split([',', ' ']) {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((a, b)) = token.split_once('-') {
            let start = parse_one(a)?;
            let end = parse_one(b)?;
            if start > end {
                return Err(PortParseError::BadRange {
                    spec: token.to_string(),
                });
            }
            let count = usize::from(end - start) + 1;
            if ports.len() + count > MAX_PORTS {
                return Err(PortParseError::TooMany {
                    count: ports.len() + count,
                    max: MAX_PORTS,
                });
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            ports.push(parse_one(token)?);
            if ports.len() > MAX_PORTS {
                return Err(PortParseError::TooMany {
                    count: ports.len(),
                    max: MAX_PORTS,
                });
            }
        }
    }

    if ports.is_empty() {
        return Err(PortParseError::Empty);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_one(token: &str) -> Result<u16, PortParseError> {
    let token = token.trim();
    if token == "0" {
        return Err(PortParseError::Invalid {
            token: token.into(),
            reason: "port 0 is not allowed".into(),
        });
    }
    token.parse::<u16>().map_err(|_| PortParseError::Invalid {
        token: token.into(),
        reason: "expected 1-65535".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_and_range() {
        assert_eq!(parse_ports("22").unwrap(), vec![22]);
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports("1-3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_ports("443, 80, 80").unwrap(), vec![80, 443]);
    }

    #[test]
    fn top_presets() {
        let t = parse_ports("top").unwrap();
        assert_eq!(t.len(), TOP_100.len());
        assert!(t.contains(&22) && t.contains(&443));
        let t1k = parse_ports("top1000").unwrap();
        assert!(t1k.len() <= 1000);
        assert!(t1k.len() >= 100);
    }

    #[test]
    fn rejects_bad() {
        assert!(matches!(parse_ports(""), Err(PortParseError::Empty)));
        assert!(matches!(
            parse_ports("0"),
            Err(PortParseError::Invalid { .. })
        ));
        assert!(matches!(
            parse_ports("5-1"),
            Err(PortParseError::BadRange { .. })
        ));
    }
}

//! Embedded service signature file (`data/signatures.keld`).

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::bytes::Regex;

/// Raw embedded signature source.
pub const EMBEDDED_SIGNATURES: &str = include_str!("../data/signatures.keld");

/// One probe definition (payload + matches).
#[derive(Debug, Clone)]
pub struct ProbeDef {
    pub name: String,
    /// Empty means all ports.
    pub ports: Vec<u16>,
    pub payload: Vec<u8>,
    pub matches: Vec<SignatureMatch>,
}

#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub service: String,
    pub product: String,
    pub pattern: Regex,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("signature line {line}: {message}")]
    Line { line: usize, message: String },
}

/// Parsed signature database.
#[derive(Debug, Clone)]
pub struct SignatureDb {
    pub probes: Vec<ProbeDef>,
}

impl SignatureDb {
    /// Parse `signatures.keld` text.
    pub fn parse(src: &str) -> Result<Self, SignatureError> {
        let mut probes: Vec<ProbeDef> = Vec::new();
        let mut by_name: HashMap<String, usize> = HashMap::new();

        for (idx, raw) in src.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (kind, after_kind) = next_word(line).ok_or_else(|| SignatureError::Line {
                line: line_no,
                message: "empty directive".into(),
            })?;
            match kind {
                "probe" => {
                    let (name, after_name) =
                        next_word(after_kind).ok_or_else(|| SignatureError::Line {
                            line: line_no,
                            message: "probe missing name".into(),
                        })?;
                    let name = name.to_string();
                    let mut ports = Vec::new();
                    let mut payload = Vec::new();
                    // payload= may contain spaces; take the rest of the line after it.
                    let (fields, payload_raw) = split_payload_field(after_name);
                    for tok in fields.split_whitespace() {
                        if tok.is_empty() {
                            continue;
                        }
                        if let Some(rest) = tok.strip_prefix("ports=") {
                            ports = parse_ports_field(rest).map_err(|message| {
                                SignatureError::Line {
                                    line: line_no,
                                    message,
                                }
                            })?;
                        } else {
                            return Err(SignatureError::Line {
                                line: line_no,
                                message: format!("unknown probe field `{tok}`"),
                            });
                        }
                    }
                    if let Some(raw) = payload_raw {
                        payload =
                            unescape_payload(raw).map_err(|message| SignatureError::Line {
                                line: line_no,
                                message,
                            })?;
                    }
                    let def = ProbeDef {
                        name: name.clone(),
                        ports,
                        payload,
                        matches: Vec::new(),
                    };
                    by_name.insert(name, probes.len());
                    probes.push(def);
                }
                "match" => {
                    let (probe_name, after_probe) =
                        next_word(after_kind).ok_or_else(|| SignatureError::Line {
                            line: line_no,
                            message: "match missing probe name".into(),
                        })?;
                    let (service, after_service) =
                        next_word(after_probe).ok_or_else(|| SignatureError::Line {
                            line: line_no,
                            message: "match missing service".into(),
                        })?;
                    let service = service.to_string();
                    let (pattern_tok, after_pattern) =
                        split_match_pattern(after_service).map_err(|message| {
                            SignatureError::Line {
                                line: line_no,
                                message,
                            }
                        })?;
                    let (pattern, case_insensitive) =
                        parse_match_pattern(pattern_tok).map_err(|message| {
                            SignatureError::Line {
                                line: line_no,
                                message,
                            }
                        })?;
                    let mut product = service.clone();
                    for tok in after_pattern.split_whitespace() {
                        if tok.is_empty() {
                            continue;
                        }
                        if let Some(rest) = tok.strip_prefix("product=") {
                            product = rest.to_string();
                        } else {
                            return Err(SignatureError::Line {
                                line: line_no,
                                message: format!("unknown match field `{tok}`"),
                            });
                        }
                    }
                    let pattern = if case_insensitive {
                        format!("(?i){pattern}")
                    } else {
                        pattern
                    };
                    let builder = Regex::new(&pattern).map_err(|e| SignatureError::Line {
                        line: line_no,
                        message: format!("bad regex: {e}"),
                    })?;
                    let idx = *by_name
                        .get(probe_name)
                        .ok_or_else(|| SignatureError::Line {
                            line: line_no,
                            message: format!("unknown probe `{probe_name}`"),
                        })?;
                    probes[idx].matches.push(SignatureMatch {
                        service,
                        product,
                        pattern: builder,
                    });
                }
                other => {
                    return Err(SignatureError::Line {
                        line: line_no,
                        message: format!("unknown directive `{other}`"),
                    });
                }
            }
        }

        if probes.is_empty() {
            return Err(SignatureError::Line {
                line: 1,
                message: "no probes defined".into(),
            });
        }
        Ok(Self { probes })
    }

    /// Embedded database (parsed once).
    pub fn embedded() -> &'static SignatureDb {
        static DB: OnceLock<SignatureDb> = OnceLock::new();
        DB.get_or_init(|| {
            SignatureDb::parse(EMBEDDED_SIGNATURES).expect("embedded signatures.keld must parse")
        })
    }

    /// Probes that apply to `port` (wildcard first as listed in the file).
    pub fn probes_for(&self, port: u16) -> Vec<&ProbeDef> {
        self.probes
            .iter()
            .filter(|p| p.ports.is_empty() || p.ports.contains(&port))
            .collect()
    }

    /// Match response bytes against a probe's signatures.
    pub fn match_response<'a>(
        &'a self,
        probe: &'a ProbeDef,
        data: &[u8],
    ) -> Option<&'a SignatureMatch> {
        probe.matches.iter().find(|m| m.pattern.is_match(data))
    }
}

fn next_word(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(i) => Some((&s[..i], s[i..].trim_start())),
        None => Some((s, "")),
    }
}

/// Split `ports=... payload=<rest of line>` from a probe field string.
fn split_payload_field(rest: &str) -> (&str, Option<&str>) {
    if let Some(idx) = rest.find("payload=") {
        let fields = rest[..idx].trim();
        let payload = &rest[idx + "payload=".len()..];
        (fields, Some(payload))
    } else {
        (rest, None)
    }
}

/// Extract `m<delim>...<delim>[flags]` from the start of a match remainder.
fn split_match_pattern(rest: &str) -> Result<(&str, &str), String> {
    let rest = rest.trim();
    if !rest.starts_with('m') || rest.len() < 3 {
        return Err("match missing m/.../ pattern".into());
    }
    let delim = rest.as_bytes()[1] as char;
    let after_open = &rest[2..];
    let mut i = 0;
    let bytes = after_open.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == delim as u8 {
            let end = 2 + i; // index of closing delim in `rest`
            let mut flags_end = end + 1;
            while flags_end < rest.len() {
                let c = rest.as_bytes()[flags_end];
                if c.is_ascii_whitespace() {
                    break;
                }
                flags_end += 1;
            }
            let pattern_tok = &rest[..flags_end];
            let after = rest[flags_end..].trim_start();
            return Ok((pattern_tok, after));
        }
        i += 1;
    }
    Err(format!("unclosed pattern delimiter `{delim}`"))
}

fn parse_ports_field(raw: &str) -> Result<Vec<u16>, String> {
    if raw == "*" || raw.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in raw.split(',') {
        let p: u16 = part
            .trim()
            .parse()
            .map_err(|_| format!("bad port `{part}`"))?;
        out.push(p);
    }
    Ok(out)
}

fn parse_match_pattern(tok: &str) -> Result<(String, bool), String> {
    let rest = tok
        .strip_prefix('m')
        .ok_or_else(|| format!("pattern must start with m/, got `{tok}`"))?;
    let bytes = rest.as_bytes();
    if bytes.len() < 2 {
        return Err("pattern too short".into());
    }
    let delim = bytes[0] as char;
    let body = &rest[1..];
    let mut i = 0;
    let b = body.as_bytes();
    let mut end = None;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == delim as u8 {
            end = Some(i);
            break;
        }
        i += 1;
    }
    let end = end.ok_or_else(|| format!("unclosed pattern delimiter `{delim}`"))?;
    let pattern = body[..end].to_string();
    let flags = &body[end + 1..];
    let case_insensitive = flags.contains('i');
    if flags.chars().any(|c| c != 'i') {
        return Err(format!("unsupported regex flags `{flags}`"));
    }
    Ok((pattern, case_insensitive))
}

fn unescape_payload(raw: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            return Err("trailing backslash in payload".into());
        }
        match bytes[i] {
            b'\\' => out.push(b'\\'),
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'0' => out.push(0),
            b'x' => {
                if i + 2 >= bytes.len() {
                    return Err("incomplete \\xHH escape".into());
                }
                let hi = hex_nibble(bytes[i + 1])?;
                let lo = hex_nibble(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 2;
            }
            other => {
                return Err(format!("unknown escape `\\{}`", other as char));
            }
        }
        i += 1;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("bad hex digit `{}`", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_parses() {
        let db = SignatureDb::embedded();
        assert!(!db.probes.is_empty());
        assert!(db.probes.iter().any(|p| p.name == "null"));
        assert!(db.probes.iter().any(|p| p.name == "httpget"));
    }

    #[test]
    fn unescape_and_match_ssh() {
        let db = SignatureDb::parse(
            r#"
probe null ports=* payload=
match null ssh m/^SSH-/i product=OpenSSH
"#,
        )
        .unwrap();
        let probe = &db.probes[0];
        let hit = db
            .match_response(probe, b"SSH-2.0-OpenSSH_9.0\r\n")
            .unwrap();
        assert_eq!(hit.service, "ssh");
        assert_eq!(hit.product, "OpenSSH");
    }

    #[test]
    fn payload_escapes() {
        assert_eq!(unescape_payload(r"a\r\n\x41").unwrap(), b"a\r\nA");
    }

    #[test]
    fn match_pattern_allows_spaces() {
        let db = SignatureDb::parse(
            r#"
probe null ports=* payload=
match null imap m/^\* OK/i product=imap
"#,
        )
        .unwrap();
        let hit = db
            .match_response(&db.probes[0], b"* OK IMAP4 ready\r\n")
            .unwrap();
        assert_eq!(hit.service, "imap");
    }

    #[test]
    fn probe_payload_allows_spaces() {
        let db = SignatureDb::parse(
            r#"
probe httpget ports=* payload=GET / HTTP/1.0\r\n\r\n
match httpget http m/^HTTP/i product=http
"#,
        )
        .unwrap();
        assert_eq!(db.probes[0].payload, b"GET / HTTP/1.0\r\n\r\n");
    }

    #[test]
    fn probes_for_filters_ports() {
        let db = SignatureDb::embedded();
        let for_80 = db.probes_for(80);
        assert!(for_80.iter().any(|p| p.name == "null"));
        assert!(for_80.iter().any(|p| p.name == "httpget"));
        let for_22 = db.probes_for(22);
        assert!(for_22.iter().any(|p| p.name == "null"));
        assert!(!for_22.iter().any(|p| p.name == "httpget"));
    }
}

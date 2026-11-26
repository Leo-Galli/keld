//! Shared CLI emitters (`--json` vs human).

use std::io::{self, Write};

use serde::Serialize;

/// Serialize `value` as one JSON document on stdout.
pub fn emit_json<T: Serialize>(value: &T) -> Result<(), String> {
    let mut out = io::stdout();
    serde_json::to_writer_pretty(&mut out, value).map_err(|e| e.to_string())?;
    writeln!(out).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Sample {
        n: u32,
    }

    #[test]
    fn emit_json_writes_object() {
        // Smoke: serialization path used by emit_json.
        let s = serde_json::to_string_pretty(&Sample { n: 1 }).unwrap();
        assert!(s.contains("\"n\": 1"));
    }
}

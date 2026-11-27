//! `keld report` -- merge findings into JSON / Markdown / HTML / CSV / SARIF.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use keld_core::{AuditEntry, AuditLog, AuditOutcome};
use keld_report::{load_paths, render, write_report, ReportDocument, ReportFormat};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct ReportJsonSummary {
    format: String,
    output: Option<String>,
    findings: usize,
    dry_run: bool,
    title: String,
    parameters: String,
}

pub struct ReportArgs {
    pub inputs: Vec<PathBuf>,
    pub format: String,
    pub output: Option<PathBuf>,
    pub title: Option<String>,
    pub dry_run: bool,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: ReportArgs, audit: &mut AuditLog) -> Result<u8, String> {
    let format = ReportFormat::parse(&args.format).ok_or_else(|| {
        format!(
            "unknown format `{}` (json|markdown|html|csv|sarif)",
            args.format
        )
    })?;

    if args.inputs.is_empty() {
        return Err("at least one --input is required".into());
    }

    let hook = PartialSaveHook::new();
    hook.install(|| {});

    let mut doc = load_paths(&args.inputs).map_err(|e| e.to_string())?;
    if let Some(title) = &args.title {
        doc.title = title.clone();
    }
    doc.touch();

    let out_path = args.output.clone();
    let params = parameters_summary(&args.inputs, format, out_path.as_ref(), &doc);
    let target = args
        .inputs
        .first()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(inputs)".into());

    if hook.is_cancelled() {
        let entry = AuditEntry::now("report", &target, &params, AuditOutcome::Cancelled);
        let _ = audit.append(entry);
        return Ok(130);
    }

    if args.dry_run {
        emit_dry_run(&args, &doc, format, out_path.as_ref())?;
        let entry = AuditEntry::now("report", &target, &params, AuditOutcome::Ok);
        audit.append(entry).map_err(|e| e.to_string())?;
        return Ok(0);
    }

    match &out_path {
        Some(path) => {
            write_report(&doc, format, path).map_err(|e| e.to_string())?;
            if args.json {
                output::emit_json(&ReportJsonSummary {
                    format: format.as_str().into(),
                    output: Some(path.display().to_string()),
                    findings: doc.findings.len(),
                    dry_run: false,
                    title: doc.title.clone(),
                    parameters: params.clone(),
                })?;
            } else {
                println!(
                    "{}",
                    args.color.green(&format!(
                        "wrote {} ({} finding(s)) to {}",
                        format.as_str(),
                        doc.findings.len(),
                        path.display()
                    ))
                );
            }
        }
        None => {
            let body = render(&doc, format).map_err(|e| e.to_string())?;
            write_stdout(&body)?;
        }
    }

    let entry = AuditEntry::now("report", &target, &params, AuditOutcome::Ok);
    audit.append(entry).map_err(|e| e.to_string())?;
    Ok(0)
}

fn write_stdout(body: &str) -> Result<(), String> {
    let mut out = io::stdout().lock();
    out.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    if !body.ends_with('\n') && io::stdout().is_terminal() {
        out.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn emit_dry_run(
    args: &ReportArgs,
    doc: &ReportDocument,
    format: ReportFormat,
    out_path: Option<&PathBuf>,
) -> Result<(), String> {
    let dest = out_path
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(stdout)".into());
    if args.json {
        return output::emit_json(&ReportJsonSummary {
            format: format.as_str().into(),
            output: out_path.map(|p| p.display().to_string()),
            findings: doc.findings.len(),
            dry_run: true,
            title: doc.title.clone(),
            parameters: parameters_summary(&args.inputs, format, out_path, doc),
        });
    }
    println!(
        "{}",
        args.color.bold(&format!(
            "dry-run: would write {} finding(s) as {} to {}",
            doc.findings.len(),
            format.as_str(),
            dest
        ))
    );
    for f in &doc.findings {
        println!(
            "  {:<8}  {:<8}  {}  {}",
            f.severity.as_str(),
            f.module,
            f.target,
            f.title
        );
    }
    Ok(())
}

fn parameters_summary(
    inputs: &[PathBuf],
    format: ReportFormat,
    out: Option<&PathBuf>,
    doc: &ReportDocument,
) -> String {
    let ins: Vec<_> = inputs.iter().map(|p| p.display().to_string()).collect();
    format!(
        "inputs={} format={} output={} findings={} title={}",
        ins.join(","),
        format.as_str(),
        out.map(|p| p.display().to_string())
            .unwrap_or_else(|| "(stdout)".into()),
        doc.findings.len(),
        if doc.title.is_empty() {
            "(none)"
        } else {
            doc.title.as_str()
        }
    )
}

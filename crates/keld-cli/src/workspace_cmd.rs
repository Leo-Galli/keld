//! `keld workspace` -- local SQLite projects (scope, findings, audit).

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use keld_core::{
    default_audit_path, AuditEntry, AuditLog, AuditOutcome, WorkspaceStore, DEFAULT_SCOPE_FILE,
};
use keld_report::{load_paths, ReportDocument};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Clone, Copy)]
pub enum WorkspaceAction {
    List,
    Create,
    Show,
    Delete,
    SetScope,
    ImportFindings,
    ExportFindings,
    ImportAudit,
}

pub struct WorkspaceArgs {
    pub action: WorkspaceAction,
    pub name: Option<String>,
    pub file: Option<PathBuf>,
    pub inputs: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub dry_run: bool,
    pub json: bool,
    pub color: ColorMode,
}

#[derive(Debug, Serialize)]
struct ListJson {
    root: String,
    workspaces: Vec<WsRow>,
}

#[derive(Debug, Serialize)]
struct WsRow {
    name: String,
    path: String,
    findings: usize,
    audit_entries: usize,
    has_scope: bool,
}

#[derive(Debug, Serialize)]
struct ShowJson {
    name: String,
    path: String,
    db: String,
    findings: usize,
    audit_entries: usize,
    has_scope: bool,
    scope_summary: String,
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct MutJson {
    action: String,
    name: String,
    dry_run: bool,
    message: String,
    findings: Option<usize>,
    audit_entries: Option<usize>,
}

pub fn run(args: WorkspaceArgs, audit: &mut AuditLog) -> Result<u8, String> {
    let hook = PartialSaveHook::new();
    hook.install(|| {});

    let store = WorkspaceStore::open_default().map_err(|e| e.to_string())?;
    let target = args.name.clone().unwrap_or_else(|| "-".into());
    let params = format!("{:?}", args.action).to_ascii_lowercase();

    if hook.is_cancelled() {
        let entry = AuditEntry::now("workspace", &target, &params, AuditOutcome::Cancelled);
        let _ = audit.append(entry);
        return Ok(130);
    }

    let code = match args.action {
        WorkspaceAction::List => run_list(&args, &store)?,
        WorkspaceAction::Create => run_create(&args, &store)?,
        WorkspaceAction::Show => run_show(&args, &store)?,
        WorkspaceAction::Delete => run_delete(&args, &store)?,
        WorkspaceAction::SetScope => run_set_scope(&args, &store)?,
        WorkspaceAction::ImportFindings => run_import_findings(&args, &store)?,
        WorkspaceAction::ExportFindings => run_export_findings(&args, &store)?,
        WorkspaceAction::ImportAudit => run_import_audit(&args, &store)?,
    };

    if hook.is_cancelled() {
        let entry = AuditEntry::now("workspace", &target, &params, AuditOutcome::Cancelled);
        let _ = audit.append(entry);
        return Ok(130);
    }

    let outcome = if code == 0 {
        AuditOutcome::Ok
    } else {
        AuditOutcome::Error
    };
    let entry = AuditEntry::now("workspace", &target, &params, outcome);
    audit.append(entry).map_err(|e| e.to_string())?;
    Ok(code)
}

fn require_name(args: &WorkspaceArgs) -> Result<&str, String> {
    args.name
        .as_deref()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| "workspace name is required".into())
}

fn run_list(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let list = store.list().map_err(|e| e.to_string())?;
    if args.json {
        output::emit_json(&ListJson {
            root: store.root().display().to_string(),
            workspaces: list
                .iter()
                .map(|w| WsRow {
                    name: w.name.clone(),
                    path: w.path.display().to_string(),
                    findings: w.findings,
                    audit_entries: w.audit_entries,
                    has_scope: w.has_scope,
                })
                .collect(),
        })?;
        return Ok(0);
    }
    println!(
        "{}",
        args.color
            .bold(&format!("workspaces ({})", store.root().display()))
    );
    if list.is_empty() {
        println!("{}", args.color.dim("(none)"));
        return Ok(0);
    }
    for w in list {
        let scope = if w.has_scope { "scope" } else { "no-scope" };
        println!(
            "  {:<16}  findings:{:<4}  audit:{:<4}  {scope}",
            w.name, w.findings, w.audit_entries
        );
    }
    Ok(0)
}

fn run_create(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    if args.dry_run {
        return emit_mut(
            args,
            "create",
            name,
            format!("would create `{name}`"),
            None,
            None,
        );
    }
    let ws = store.create(name).map_err(|e| e.to_string())?;
    let msg = format!("created `{}` at {}", ws.name(), ws.dir().display());
    if args.json {
        emit_mut(args, "create", name, msg, Some(0), Some(0))
    } else {
        println!("{}", args.color.green(&msg));
        Ok(0)
    }
}

fn run_show(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    let ws = store.open_workspace(name).map_err(|e| e.to_string())?;
    let stats = ws.stats().map_err(|e| e.to_string())?;
    if args.json {
        output::emit_json(&ShowJson {
            name: ws.name().into(),
            path: ws.dir().display().to_string(),
            db: ws.db_path().display().to_string(),
            findings: stats.findings,
            audit_entries: stats.audit_entries,
            has_scope: stats.has_scope,
            scope_summary: stats.scope_summary,
            dry_run: args.dry_run,
        })?;
        return Ok(0);
    }
    println!("{}", args.color.bold(&format!("workspace `{name}`")));
    println!("  path:   {}", ws.dir().display());
    println!("  db:     {}", ws.db_path().display());
    println!("  scope:  {}", stats.scope_summary);
    println!("  findings: {}", stats.findings);
    println!("  audit:    {}", stats.audit_entries);
    Ok(0)
}

fn run_delete(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    if args.dry_run {
        return emit_mut(
            args,
            "delete",
            name,
            format!("would delete `{name}`"),
            None,
            None,
        );
    }
    store.delete(name).map_err(|e| e.to_string())?;
    let msg = format!("deleted `{name}`");
    if args.json {
        emit_mut(args, "delete", name, msg, None, None)
    } else {
        println!("{}", args.color.yellow(&msg));
        Ok(0)
    }
}

fn run_set_scope(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    let path = args
        .file
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SCOPE_FILE));
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if args.dry_run {
        return emit_mut(
            args,
            "set-scope",
            name,
            format!("would set scope from {}", path.display()),
            None,
            None,
        );
    }
    let ws = store.open_workspace(name).map_err(|e| e.to_string())?;
    let scope = ws.set_scope_toml(&text).map_err(|e| e.to_string())?;
    let msg = format!("scope set ({})", scope.summary());
    if args.json {
        emit_mut(args, "set-scope", name, msg, None, None)
    } else {
        println!("{}", args.color.green(&msg));
        Ok(0)
    }
}

fn run_import_findings(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    if args.inputs.is_empty() {
        return Err("at least one --input is required".into());
    }
    let doc = load_paths(&args.inputs).map_err(|e| e.to_string())?;
    if args.dry_run {
        return emit_mut(
            args,
            "import-findings",
            name,
            format!("would import {} finding(s)", doc.findings.len()),
            Some(doc.findings.len()),
            None,
        );
    }
    let ws = store.open_workspace(name).map_err(|e| e.to_string())?;
    ws.upsert_findings(&doc.findings)
        .map_err(|e| e.to_string())?;
    let stats = ws.stats().map_err(|e| e.to_string())?;
    let msg = format!(
        "imported {}; workspace now has {} finding(s)",
        doc.findings.len(),
        stats.findings
    );
    if args.json {
        emit_mut(
            args,
            "import-findings",
            name,
            msg,
            Some(stats.findings),
            Some(stats.audit_entries),
        )
    } else {
        println!("{}", args.color.green(&msg));
        Ok(0)
    }
}

fn run_export_findings(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    let ws = store.open_workspace(name).map_err(|e| e.to_string())?;
    let findings = ws.list_findings().map_err(|e| e.to_string())?;
    let mut doc = ReportDocument::empty().with_findings(findings);
    doc.title = format!("workspace:{name}");
    doc.touch();

    if args.dry_run {
        return emit_mut(
            args,
            "export-findings",
            name,
            format!("would export {} finding(s)", doc.findings.len()),
            Some(doc.findings.len()),
            None,
        );
    }

    let body = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    match &args.output {
        Some(path) => {
            fs::write(path, &body).map_err(|e| format!("{}: {e}", path.display()))?;
            let msg = format!(
                "wrote {} finding(s) to {}",
                doc.findings.len(),
                path.display()
            );
            if args.json {
                emit_mut(
                    args,
                    "export-findings",
                    name,
                    msg,
                    Some(doc.findings.len()),
                    None,
                )
            } else {
                println!("{}", args.color.green(&msg));
                Ok(0)
            }
        }
        None => {
            let mut out = io::stdout().lock();
            out.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
            if !body.ends_with('\n') {
                out.write_all(b"\n").map_err(|e| e.to_string())?;
            }
            Ok(0)
        }
    }
}

fn run_import_audit(args: &WorkspaceArgs, store: &WorkspaceStore) -> Result<u8, String> {
    let name = require_name(args)?;
    let path = args.file.clone().unwrap_or_else(default_audit_path);
    let log = AuditLog::load(&path).map_err(|e| e.to_string())?;
    let entries = log.entries().to_vec();
    if args.dry_run {
        return emit_mut(
            args,
            "import-audit",
            name,
            format!(
                "would import {} audit entr(y/ies) from {}",
                entries.len(),
                path.display()
            ),
            None,
            Some(entries.len()),
        );
    }
    let ws = store.open_workspace(name).map_err(|e| e.to_string())?;
    ws.append_audit_many(&entries).map_err(|e| e.to_string())?;
    let stats = ws.stats().map_err(|e| e.to_string())?;
    let msg = format!(
        "imported {}; workspace now has {} audit entr(y/ies)",
        entries.len(),
        stats.audit_entries
    );
    if args.json {
        emit_mut(
            args,
            "import-audit",
            name,
            msg,
            Some(stats.findings),
            Some(stats.audit_entries),
        )
    } else {
        println!("{}", args.color.green(&msg));
        Ok(0)
    }
}

fn emit_mut(
    args: &WorkspaceArgs,
    action: &str,
    name: &str,
    message: String,
    findings: Option<usize>,
    audit_entries: Option<usize>,
) -> Result<u8, String> {
    if args.json {
        output::emit_json(&MutJson {
            action: action.into(),
            name: name.into(),
            dry_run: args.dry_run,
            message,
            findings,
            audit_entries,
        })?;
    } else if args.dry_run {
        println!("{}", args.color.bold(&message));
    } else {
        println!("{}", args.color.green(&message));
    }
    Ok(0)
}

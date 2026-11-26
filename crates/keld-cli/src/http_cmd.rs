//! `keld http` -- security headers, cookies, CORS, fingerprint, robots/sitemap.

use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    HttpConfig, HttpFinding, HttpModule, DEFAULT_HTTP_CONCURRENCY, DEFAULT_HTTP_TIMEOUT_MS,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct HttpJson {
    target: String,
    dry_run: bool,
    findings: Vec<HttpJsonFinding>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct HttpJsonFinding {
    url: String,
    severity: String,
    kind: String,
    detail: String,
    planned: bool,
}

pub struct HttpArgs {
    pub target: String,
    pub timeout_ms: u64,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: HttpArgs, scope: &Scope, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_HTTP_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_HTTP_TIMEOUT_MS
    } else {
        args.timeout_ms
    };

    let config = HttpConfig::from_parts(
        args.target.clone(),
        timeout_ms,
        concurrency,
        args.dry_run,
        args.rate,
    )
    .map_err(|e| e.to_string())?;

    // Scope gate uses host extracted inside the module; pre-check via dry config target host.
    if let Err(e) = precheck_scope(scope, &config.target) {
        let entry = AuditEntry::now(
            "http",
            config.target.clone(),
            config.parameters_summary(),
            AuditOutcome::Denied,
        );
        let _ = audit.append(entry);
        return Err(e);
    }

    let partial: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let hook = PartialSaveHook::new();
    {
        let partial = Arc::clone(&partial);
        let color = args.color;
        hook.install(move || {
            if let Ok(guard) = partial.lock() {
                if guard.is_empty() {
                    eprintln!("{}", color.yellow("interrupted; no HTTP findings yet"));
                } else {
                    eprintln!(
                        "{}",
                        color.yellow(&format!("interrupted; partial findings ({}):", guard.len()))
                    );
                    for line in guard.iter() {
                        eprintln!("{line}");
                    }
                }
            }
        });
    }

    let bus = EventBus::with_defaults();
    let mut rx = bus.subscribe();
    let module = HttpModule::new(config.clone(), scope.clone());
    let job_id = JobId::new(1);

    let bar = if args.json || args.dry_run {
        None
    } else {
        let pb = ProgressBar::new(4);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-"),
        );
        Some(pb)
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    let sender = bus.sender();
    let http_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_http(job_id, sender).await });

        let drain = tokio::spawn({
            let partial = Arc::clone(&partial);
            let bar = bar.clone();
            async move {
                loop {
                    match rx.recv().await {
                        Ok(ModuleEvent::Progress {
                            done,
                            total,
                            message,
                            ..
                        }) => {
                            if let Some(pb) = &bar {
                                pb.set_length(total);
                                pb.set_position(done);
                                pb.set_message(message);
                            }
                        }
                        Ok(ModuleEvent::Result { summary, .. }) => {
                            if let Ok(mut g) = partial.lock() {
                                g.push(summary);
                            }
                        }
                        Ok(ModuleEvent::Done { .. }) | Ok(ModuleEvent::Error { .. }) => break,
                        Ok(ModuleEvent::Log { .. }) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        });

        let findings = handle
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let _ = drain.await;
        Ok::<_, String>(findings)
    });

    if let Some(pb) = bar {
        pb.finish_and_clear();
    }

    if hook.is_cancelled() {
        let entry = AuditEntry::now(
            "http",
            config.target.clone(),
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let findings = match http_result {
        Ok(findings) => findings,
        Err(e) => {
            let entry = AuditEntry::now(
                "http",
                config.target.clone(),
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "http",
        config.target.clone(),
        config.parameters_summary(),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &findings)?;
    Ok(0)
}

fn precheck_scope(scope: &Scope, target: &str) -> Result<(), String> {
    let host = if let Some(rest) = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .or_else(|| {
            if target.contains("://") {
                None
            } else {
                Some(target)
            }
        }) {
        rest.split(['/', ':', '?', '#'])
            .next()
            .unwrap_or(rest)
            .trim_matches(|c| c == '[' || c == ']')
    } else {
        target
    };
    scope.check(host).map_err(|e| e.to_string())
}

fn emit_results(
    args: &HttpArgs,
    config: &HttpConfig,
    findings: &[HttpFinding],
) -> Result<(), String> {
    if args.json {
        let doc = HttpJson {
            target: config.target.clone(),
            dry_run: config.dry_run,
            findings: findings
                .iter()
                .map(|f| HttpJsonFinding {
                    url: f.url.clone(),
                    severity: f.severity.as_str().into(),
                    kind: f.kind.clone(),
                    detail: f.detail.clone(),
                    planned: f.planned,
                })
                .collect(),
            parameters: config.parameters_summary(),
        };
        return output::emit_json(&doc);
    }

    if config.dry_run {
        println!(
            "{}",
            args.color.bold(&format!(
                "dry-run: would audit {}",
                findings
                    .first()
                    .map(|f| f.url.as_str())
                    .unwrap_or(&config.target)
            ))
        );
        return Ok(());
    }

    if findings.is_empty() {
        println!(
            "{}",
            args.color
                .dim(&format!("no HTTP findings for {}", config.target))
        );
    } else {
        println!(
            "{}",
            args.color
                .green(&format!("HTTP findings for {}:", config.target))
        );
        for f in findings {
            let sev = f.severity.as_str();
            println!("  [{sev:<8}] {:<10} {}", f.kind, f.detail);
        }
    }
    Ok(())
}

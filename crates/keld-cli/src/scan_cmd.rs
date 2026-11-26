//! `keld scan` -- TCP connect port scanner, with an optional SYN request.

use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    PortState, ScanConfig, ScanModule, ScanReport, ScanTechnique, DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT_MS,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct ScanJson {
    target: String,
    dry_run: bool,
    technique: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<String>,
    open: Vec<ScanJsonHit>,
    planned: Vec<ScanJsonHit>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct ScanJsonHit {
    host: String,
    port: u16,
    state: String,
}

pub struct ScanArgs {
    pub target: String,
    pub ports: String,
    pub timeout_ms: u64,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
    pub syn: bool,
}

pub fn run(args: ScanArgs, scope: &Scope, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        args.timeout_ms
    };

    let mut config = ScanConfig::from_parts(
        args.target.clone(),
        &args.ports,
        timeout_ms,
        concurrency,
        args.dry_run,
        args.rate,
    )
    .map_err(|e| e.to_string())?;
    if args.syn {
        config.technique = ScanTechnique::Syn;
    }

    if let Err(e) = scope.check(&config.target) {
        let entry = AuditEntry::now(
            "scan",
            config.target.clone(),
            config.parameters_summary(),
            AuditOutcome::Denied,
        );
        let _ = audit.append(entry);
        return Err(e.to_string());
    }

    let partial: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let hook = PartialSaveHook::new();
    {
        let partial = Arc::clone(&partial);
        let color = args.color;
        hook.install(move || {
            if let Ok(guard) = partial.lock() {
                if guard.is_empty() {
                    eprintln!("{}", color.yellow("interrupted; no open ports yet"));
                } else {
                    eprintln!(
                        "{}",
                        color.yellow(&format!(
                            "interrupted; partial open ports ({}):",
                            guard.len()
                        ))
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
    let module = ScanModule::new(config.clone(), scope.clone());
    let job_id = JobId::new(1);

    let bar = if args.json || args.dry_run {
        None
    } else {
        let pb = ProgressBar::new(config.ports.len() as u64);
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
    let scan_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_scan(job_id, sender).await });

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

        let report = handle
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let _ = drain.await;
        Ok::<_, String>(report)
    });

    if let Some(pb) = bar {
        pb.finish_and_clear();
    }

    if hook.is_cancelled() {
        let entry = AuditEntry::now(
            "scan",
            config.target.clone(),
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let report = match scan_result {
        Ok(report) => report,
        Err(e) => {
            let entry = AuditEntry::now(
                "scan",
                config.target.clone(),
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "scan",
        config.target.clone(),
        report.audit_parameters(&config),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &report)?;
    Ok(0)
}

fn emit_results(args: &ScanArgs, config: &ScanConfig, report: &ScanReport) -> Result<(), String> {
    let hits = &report.hits;
    if args.json {
        let open: Vec<ScanJsonHit> = hits
            .iter()
            .filter(|h| h.state == PortState::Open)
            .map(|h| ScanJsonHit {
                host: h.host.clone(),
                port: h.port,
                state: h.state.as_str().into(),
            })
            .collect();
        let planned: Vec<ScanJsonHit> = hits
            .iter()
            .filter(|h| h.state == PortState::Planned)
            .map(|h| ScanJsonHit {
                host: h.host.clone(),
                port: h.port,
                state: h.state.as_str().into(),
            })
            .collect();
        let doc = ScanJson {
            target: config.target.clone(),
            dry_run: config.dry_run,
            technique: report.used.as_str().into(),
            fallback: report.fallback.clone(),
            open,
            planned,
            parameters: report.audit_parameters(config),
        };
        return output::emit_json(&doc);
    }

    if let Some(fallback) = &report.fallback {
        println!("{}", args.color.yellow(fallback));
    }

    let via = match report.used {
        ScanTechnique::Syn => "SYN",
        ScanTechnique::Connect => "TCP connect",
    };

    if config.dry_run {
        println!(
            "{}",
            args.color.bold(&format!(
                "dry-run: would {via} {} ports on {}",
                hits.len(),
                config.target
            ))
        );
        for h in hits {
            println!("  {}:{} {}", h.host, h.port, h.state);
        }
        return Ok(());
    }

    if hits.is_empty() {
        println!(
            "{}",
            args.color.dim(&format!(
                "no open ports on {} ({} probed, {via})",
                config.target,
                config.ports.len()
            ))
        );
    } else {
        println!(
            "{}",
            args.color.green(&format!(
                "open ports on {} ({}/{}, {via}):",
                config.target,
                hits.len(),
                config.ports.len()
            ))
        );
        for h in hits {
            println!("  {:>5}/tcp  {}", h.port, h.state);
        }
    }
    Ok(())
}

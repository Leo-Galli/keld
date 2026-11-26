//! `keld probe` -- banner / service detection from embedded signatures.

use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    ProbeConfig, ProbeHit, ProbeModule, DEFAULT_PROBE_CONCURRENCY, DEFAULT_PROBE_TIMEOUT_MS,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct ProbeJson {
    target: String,
    dry_run: bool,
    hits: Vec<ProbeJsonHit>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct ProbeJsonHit {
    host: String,
    port: u16,
    service: String,
    product: String,
    banner: String,
    probe: String,
    planned: bool,
}

pub struct ProbeArgs {
    pub target: String,
    pub ports: String,
    pub timeout_ms: u64,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: ProbeArgs, scope: &Scope, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_PROBE_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_PROBE_TIMEOUT_MS
    } else {
        args.timeout_ms
    };

    let config = ProbeConfig::from_parts(
        args.target.clone(),
        &args.ports,
        timeout_ms,
        concurrency,
        args.dry_run,
        args.rate,
    )
    .map_err(|e| e.to_string())?;

    if let Err(e) = scope.check(&config.target) {
        let entry = AuditEntry::now(
            "probe",
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
                    eprintln!("{}", color.yellow("interrupted; no probe hits yet"));
                } else {
                    eprintln!(
                        "{}",
                        color.yellow(&format!("interrupted; partial hits ({}):", guard.len()))
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
    let module = ProbeModule::new(config.clone(), scope.clone());
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
    let probe_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_probe(job_id, sender).await });

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

        let hits = handle
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let _ = drain.await;
        Ok::<_, String>(hits)
    });

    if let Some(pb) = bar {
        pb.finish_and_clear();
    }

    if hook.is_cancelled() {
        let entry = AuditEntry::now(
            "probe",
            config.target.clone(),
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let hits = match probe_result {
        Ok(hits) => hits,
        Err(e) => {
            let entry = AuditEntry::now(
                "probe",
                config.target.clone(),
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "probe",
        config.target.clone(),
        config.parameters_summary(),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &hits)?;
    Ok(0)
}

fn emit_results(args: &ProbeArgs, config: &ProbeConfig, hits: &[ProbeHit]) -> Result<(), String> {
    if args.json {
        let doc = ProbeJson {
            target: config.target.clone(),
            dry_run: config.dry_run,
            hits: hits
                .iter()
                .map(|h| ProbeJsonHit {
                    host: h.host.clone(),
                    port: h.port,
                    service: h.service.clone(),
                    product: h.product.clone(),
                    banner: h.banner.clone(),
                    probe: h.probe_name.clone(),
                    planned: h.planned,
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
                "dry-run: would probe {} ports on {}",
                hits.len(),
                config.target
            ))
        );
        for h in hits {
            println!("  {}:{} probes=[{}]", h.host, h.port, h.probe_name);
        }
        return Ok(());
    }

    if hits.is_empty() {
        println!(
            "{}",
            args.color.dim(&format!(
                "no service matches on {} ({} probed)",
                config.target,
                config.ports.len()
            ))
        );
    } else {
        println!(
            "{}",
            args.color.green(&format!(
                "services on {} ({}/{}):",
                config.target,
                hits.len(),
                config.ports.len()
            ))
        );
        for h in hits {
            let banner = if h.banner.is_empty() {
                String::new()
            } else {
                format!("  {}", h.banner)
            };
            println!(
                "  {:>5}/tcp  {:<12} {} [{}]{}",
                h.port, h.service, h.product, h.probe_name, banner
            );
        }
    }
    Ok(())
}

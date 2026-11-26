//! `keld dns` -- records, AXFR check, wordlist + CT subdomains.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    DnsConfig, DnsHit, DnsKind, DnsModule, DnsRunOpts, DEFAULT_DNS_CONCURRENCY,
    DEFAULT_DNS_TIMEOUT_MS,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct DnsJson {
    domain: String,
    dry_run: bool,
    hits: Vec<DnsJsonHit>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct DnsJsonHit {
    kind: String,
    name: String,
    rtype: String,
    value: String,
    severity: String,
    planned: bool,
}

pub struct DnsArgs {
    pub domain: String,
    pub wordlist: Option<PathBuf>,
    pub ct: bool,
    pub timeout_ms: u64,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: DnsArgs, scope: &Scope, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_DNS_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_DNS_TIMEOUT_MS
    } else {
        args.timeout_ms
    };

    let config = DnsConfig::from_parts(
        args.domain.clone(),
        args.wordlist.clone(),
        args.ct,
        DnsRunOpts {
            timeout_ms,
            concurrency,
            dry_run: args.dry_run,
            rate_per_sec: args.rate,
        },
    )
    .map_err(|e| e.to_string())?;

    if let Err(e) = scope.check(&config.domain) {
        let entry = AuditEntry::now(
            "dns",
            config.domain.clone(),
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
                    eprintln!("{}", color.yellow("interrupted; no dns hits yet"));
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
    let module = DnsModule::new(config.clone(), scope.clone());
    let job_id = JobId::new(1);

    let bar = if args.json || args.dry_run {
        None
    } else {
        let pb = ProgressBar::new(1);
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
    let dns_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_dns(job_id, sender).await });

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
            "dns",
            config.domain.clone(),
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let hits = match dns_result {
        Ok(hits) => hits,
        Err(e) => {
            let entry = AuditEntry::now(
                "dns",
                config.domain.clone(),
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "dns",
        config.domain.clone(),
        config.parameters_summary(),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &hits)?;
    Ok(0)
}

fn emit_results(args: &DnsArgs, config: &DnsConfig, hits: &[DnsHit]) -> Result<(), String> {
    if args.json {
        let doc = DnsJson {
            domain: config.domain.clone(),
            dry_run: config.dry_run,
            hits: hits
                .iter()
                .map(|h| DnsJsonHit {
                    kind: h.kind.as_str().into(),
                    name: h.name.clone(),
                    rtype: h.rtype.clone(),
                    value: h.value.clone(),
                    severity: h.severity.as_str().into(),
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
            args.color
                .bold(&format!("dry-run: would run {} DNS step(s)", hits.len()))
        );
        for h in hits.iter().take(30) {
            println!(
                "  {:<10}  {:<8}  {}  {}",
                h.kind.as_str(),
                h.rtype,
                h.name,
                h.value
            );
        }
        if hits.len() > 30 {
            println!("  ... {} more", hits.len() - 30);
        }
        return Ok(());
    }

    if hits.is_empty() {
        println!(
            "{}",
            args.color
                .dim(&format!("no dns findings for {}", config.domain))
        );
        return Ok(());
    }

    println!(
        "{}",
        args.color
            .green(&format!("dns findings for {}:", config.domain))
    );
    for h in hits {
        let line = format!(
            "  [{:<7}] {:<10} {:<8} {}  {}",
            h.severity.as_str(),
            h.kind.as_str(),
            h.rtype,
            h.name,
            h.value
        );
        if h.kind == DnsKind::Axfr && h.severity == keld_modules::DnsSeverity::High {
            println!("{}", args.color.red(&line));
        } else {
            println!("{line}");
        }
    }
    Ok(())
}

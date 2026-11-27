//! `keld net` -- local interfaces and authorized subnet discovery.

use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    DiscoverTechnique, NetConfig, NetHit, NetModule, NetRunOpts, DEFAULT_NET_CONCURRENCY,
    DEFAULT_NET_TIMEOUT_MS,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct NetJson {
    target: Option<String>,
    dry_run: bool,
    hits: Vec<NetJsonHit>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct NetJsonHit {
    method: String,
    target: String,
    detail: String,
    planned: bool,
}

pub struct NetArgs {
    pub target: Option<String>,
    pub technique: String,
    pub ports: String,
    pub timeout_ms: u64,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: NetArgs, scope: &Scope, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_NET_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_NET_TIMEOUT_MS
    } else {
        args.timeout_ms
    };
    let technique = DiscoverTechnique::parse(&args.technique).ok_or_else(|| {
        format!(
            "invalid technique `{}` (expected auto, arp, icmp, or tcp)",
            args.technique
        )
    })?;

    let config = NetConfig::from_parts(
        args.target.clone(),
        technique,
        args.ports.clone(),
        NetRunOpts {
            timeout_ms,
            concurrency,
            dry_run: args.dry_run,
            rate_per_sec: args.rate,
        },
    )
    .map_err(|e| e.to_string())?;

    if let Some(target) = &config.target {
        if let Err(e) = scope.check(target) {
            let entry = AuditEntry::now(
                "net",
                target.clone(),
                config.parameters_summary(),
                AuditOutcome::Denied,
            );
            let _ = audit.append(entry);
            return Err(e.to_string());
        }
    }

    let audit_target = config
        .target
        .clone()
        .unwrap_or_else(|| "(interfaces)".into());

    let partial: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let hook = PartialSaveHook::new();
    {
        let partial = Arc::clone(&partial);
        let color = args.color;
        hook.install(move || {
            if let Ok(guard) = partial.lock() {
                if guard.is_empty() {
                    eprintln!("{}", color.yellow("interrupted; no net hits yet"));
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
    let module = NetModule::new(config.clone(), scope.clone());
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
    let net_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_net(job_id, sender).await });

        let drain = tokio::spawn({
            let partial = Arc::clone(&partial);
            let bar = bar.clone();
            let color = args.color;
            let quiet_logs = args.json;
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
                        Ok(ModuleEvent::Log { message, .. }) => {
                            if !quiet_logs {
                                eprintln!("{}", color.yellow(&message));
                            }
                        }
                        Ok(ModuleEvent::Done { .. }) | Ok(ModuleEvent::Error { .. }) => break,
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
            "net",
            audit_target,
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let hits = match net_result {
        Ok(hits) => hits,
        Err(e) => {
            let entry = AuditEntry::now(
                "net",
                audit_target,
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "net",
        audit_target,
        config.parameters_summary(),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &hits)?;
    Ok(0)
}

fn emit_results(args: &NetArgs, config: &NetConfig, hits: &[NetHit]) -> Result<(), String> {
    if args.json {
        let doc = NetJson {
            target: config.target.clone(),
            dry_run: config.dry_run,
            hits: hits
                .iter()
                .map(|h| NetJsonHit {
                    method: h.method.as_str().into(),
                    target: h.target.clone(),
                    detail: h.detail.clone(),
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
                .bold(&format!("dry-run: would run {} net step(s)", hits.len()))
        );
        for h in hits.iter().take(40) {
            println!("  {:<8}  {:<18}  {}", h.method.as_str(), h.target, h.detail);
        }
        if hits.len() > 40 {
            println!("  ... {} more", hits.len() - 40);
        }
        return Ok(());
    }

    let ifaces: Vec<_> = hits
        .iter()
        .filter(|h| h.method == keld_modules::DiscoverMethod::Interface)
        .collect();
    let hosts: Vec<_> = hits
        .iter()
        .filter(|h| h.method != keld_modules::DiscoverMethod::Interface)
        .collect();

    if !ifaces.is_empty() {
        println!("{}", args.color.green("interfaces:"));
        for h in &ifaces {
            println!("  {:<16}  {}  ({})", h.detail, h.target, h.method.as_str());
        }
    }

    if config.target.is_none() {
        if ifaces.is_empty() {
            println!("{}", args.color.dim("no interfaces found"));
        }
        return Ok(());
    }

    if hosts.is_empty() {
        println!(
            "{}",
            args.color.dim(&format!(
                "no hosts up for {}",
                config.target.as_deref().unwrap_or("?")
            ))
        );
        return Ok(());
    }

    println!(
        "{}",
        args.color.green(&format!(
            "hosts up for {}:",
            config.target.as_deref().unwrap_or("?")
        ))
    );
    for h in hosts {
        println!("  {:<18}  {:<6}  {}", h.target, h.method.as_str(), h.detail);
    }
    Ok(())
}

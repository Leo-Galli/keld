//! `keld hash` -- hash type ID and offline wordlist check.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent};
use keld_modules::{
    HashAlgo, HashConfig, HashHit, HashModule, HashRunOpts, DEFAULT_HASH_CONCURRENCY,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct HashJson {
    hash: String,
    dry_run: bool,
    hits: Vec<HashJsonHit>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct HashJsonHit {
    kind: String,
    algo: String,
    detail: String,
    planned: bool,
}

pub struct HashArgs {
    pub hash: String,
    pub wordlist: Option<PathBuf>,
    pub algo: String,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: HashArgs, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_HASH_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let algo = HashAlgo::parse_force(&args.algo).map_err(|e| e.to_string())?;

    let config = HashConfig::from_parts(
        args.hash.clone(),
        args.wordlist.clone(),
        algo,
        HashRunOpts {
            concurrency,
            dry_run: args.dry_run,
            rate_per_sec: args.rate,
        },
    )
    .map_err(|e| e.to_string())?;

    let audit_target = truncate_hash(&config.hash);

    let partial: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let hook = PartialSaveHook::new();
    {
        let partial = Arc::clone(&partial);
        let color = args.color;
        hook.install(move || {
            if let Ok(guard) = partial.lock() {
                if guard.is_empty() {
                    eprintln!("{}", color.yellow("interrupted; no hash hits yet"));
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
    let module = HashModule::new(config.clone());
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
    let hash_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_hash(job_id, sender).await });

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
            "hash",
            audit_target,
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let hits = match hash_result {
        Ok(hits) => hits,
        Err(e) => {
            let entry = AuditEntry::now(
                "hash",
                audit_target,
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "hash",
        audit_target,
        config.parameters_summary(),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &hits)?;
    Ok(0)
}

fn emit_results(args: &HashArgs, config: &HashConfig, hits: &[HashHit]) -> Result<(), String> {
    if args.json {
        let doc = HashJson {
            hash: config.hash.clone(),
            dry_run: config.dry_run,
            hits: hits
                .iter()
                .map(|h| HashJsonHit {
                    kind: h.kind.as_str().into(),
                    algo: h.algo.as_str().into(),
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
                .bold(&format!("dry-run: would run {} hash step(s)", hits.len()))
        );
        for h in hits {
            println!(
                "  {:<10}  {:<12}  {}",
                h.kind.as_str(),
                h.algo.as_str(),
                h.detail
            );
        }
        return Ok(());
    }

    let ids: Vec<_> = hits
        .iter()
        .filter(|h| h.kind == keld_modules::HashKind::Identify)
        .collect();
    let matches: Vec<_> = hits
        .iter()
        .filter(|h| h.kind == keld_modules::HashKind::Match)
        .collect();
    let misses: Vec<_> = hits
        .iter()
        .filter(|h| h.kind == keld_modules::HashKind::Miss)
        .collect();

    if !ids.is_empty() {
        println!("{}", args.color.green("identified:"));
        for h in &ids {
            println!("  {:<12}  {}", h.algo.as_str(), h.detail);
        }
    }

    if !matches.is_empty() {
        println!("{}", args.color.green("match:"));
        for h in &matches {
            println!("  {:<12}  {}", h.algo.as_str(), h.detail);
        }
    }

    if !misses.is_empty() {
        for h in &misses {
            println!("{}", args.color.dim(&format!("no match: {}", h.detail)));
        }
    }

    if ids.is_empty() && matches.is_empty() && misses.is_empty() {
        println!("{}", args.color.dim("no hash findings"));
    }

    Ok(())
}

fn truncate_hash(hash: &str) -> String {
    let chars: String = hash.chars().take(16).collect();
    if hash.chars().count() > 16 {
        format!("{chars}...")
    } else {
        chars
    }
}

//! `keld fuzz` -- directory and virtual-host wordlist discovery.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};
use keld_core::{AuditEntry, AuditLog, AuditOutcome, EventBus, JobId, ModuleEvent, Scope};
use keld_modules::{
    parse_u16_list, parse_u64_list, FuzzConfig, FuzzFilters, FuzzHit, FuzzMode, FuzzModule,
    FuzzRunOpts, DEFAULT_FILTER_STATUS, DEFAULT_FUZZ_CONCURRENCY, DEFAULT_FUZZ_TIMEOUT_MS,
};
use serde::Serialize;

use crate::color::ColorMode;
use crate::output;
use crate::signal::PartialSaveHook;

#[derive(Debug, Serialize)]
struct FuzzJson {
    target: String,
    mode: String,
    dry_run: bool,
    hits: Vec<FuzzJsonHit>,
    parameters: String,
}

#[derive(Debug, Serialize)]
struct FuzzJsonHit {
    mode: String,
    word: String,
    url: String,
    host_header: Option<String>,
    status: u16,
    size: u64,
    planned: bool,
}

pub struct FuzzArgs {
    pub target: String,
    pub wordlist: PathBuf,
    pub mode: String,
    pub filter_status: String,
    pub match_status: String,
    pub filter_size: String,
    pub timeout_ms: u64,
    pub concurrency: u32,
    pub dry_run: bool,
    pub rate: Option<u32>,
    pub json: bool,
    pub color: ColorMode,
}

pub fn run(args: FuzzArgs, scope: &Scope, audit: &mut AuditLog) -> Result<u8, String> {
    let concurrency = if args.concurrency == 0 {
        DEFAULT_FUZZ_CONCURRENCY
    } else {
        args.concurrency as usize
    };
    let timeout_ms = if args.timeout_ms == 0 {
        DEFAULT_FUZZ_TIMEOUT_MS
    } else {
        args.timeout_ms
    };
    let mode = FuzzMode::parse(&args.mode).ok_or_else(|| {
        format!(
            "invalid mode `{}` (expected dir or vhost)",
            args.mode.trim()
        )
    })?;
    let filters = FuzzFilters {
        filter_status: if args.filter_status.trim().is_empty() {
            DEFAULT_FILTER_STATUS.to_vec()
        } else {
            parse_u16_list(&args.filter_status)?
        },
        match_status: parse_u16_list(&args.match_status)?,
        filter_size: parse_u64_list(&args.filter_size)?,
    };

    let config = FuzzConfig::from_parts(
        args.target.clone(),
        args.wordlist.clone(),
        mode,
        FuzzRunOpts {
            timeout_ms,
            concurrency,
            dry_run: args.dry_run,
            rate_per_sec: args.rate,
        },
        filters,
    )
    .map_err(|e| e.to_string())?;

    if let Err(e) = precheck_scope(scope, &config.target) {
        let entry = AuditEntry::now(
            "fuzz",
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
                    eprintln!("{}", color.yellow("interrupted; no fuzz hits yet"));
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
    let module = FuzzModule::new(config.clone(), scope.clone());
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
    let fuzz_result = rt.block_on(async {
        let handle = tokio::spawn(async move { module.run_fuzz(job_id, sender).await });

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
            "fuzz",
            config.target.clone(),
            config.parameters_summary(),
            AuditOutcome::Cancelled,
        );
        let _ = audit.append(entry);
        return Ok(130);
    }

    let hits = match fuzz_result {
        Ok(hits) => hits,
        Err(e) => {
            let entry = AuditEntry::now(
                "fuzz",
                config.target.clone(),
                config.parameters_summary(),
                AuditOutcome::Error,
            );
            let _ = audit.append(entry);
            return Err(e);
        }
    };

    let entry = AuditEntry::now(
        "fuzz",
        config.target.clone(),
        config.parameters_summary(),
        AuditOutcome::Ok,
    );
    audit.append(entry).map_err(|e| e.to_string())?;

    emit_results(&args, &config, &hits)?;
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

fn emit_results(args: &FuzzArgs, config: &FuzzConfig, hits: &[FuzzHit]) -> Result<(), String> {
    if args.json {
        let doc = FuzzJson {
            target: config.target.clone(),
            mode: config.mode.as_str().into(),
            dry_run: config.dry_run,
            hits: hits
                .iter()
                .map(|h| FuzzJsonHit {
                    mode: h.mode.as_str().into(),
                    word: h.word.clone(),
                    url: h.url.clone(),
                    host_header: h.host_header.clone(),
                    status: h.status,
                    size: h.size,
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
                "dry-run: would probe {} word(s) ({})",
                hits.len(),
                config.mode.as_str()
            ))
        );
        for h in hits.iter().take(20) {
            match &h.host_header {
                Some(host) => println!("  {}  Host: {host}  {}", h.word, h.url),
                None => println!("  {}  {}", h.word, h.url),
            }
        }
        if hits.len() > 20 {
            println!("  ... {} more", hits.len() - 20);
        }
        return Ok(());
    }

    if hits.is_empty() {
        println!(
            "{}",
            args.color
                .dim(&format!("no fuzz hits for {}", config.target))
        );
    } else {
        println!(
            "{}",
            args.color.green(&format!(
                "fuzz hits for {} ({}):",
                config.target,
                config.mode.as_str()
            ))
        );
        for h in hits {
            match &h.host_header {
                Some(host) => {
                    println!(
                        "  {:>3}  {:>8}  Host:{:<24}  {}",
                        h.status, h.size, host, h.word
                    );
                }
                None => {
                    println!("  {:>3}  {:>8}  {}", h.status, h.size, h.url);
                }
            }
        }
    }
    Ok(())
}

//! HTTP security audit: headers, cookies, CORS, fingerprint, robots/sitemap.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use keld_core::{EventSender, JobId, ModuleEvent, ModuleKind, RateLimiter, Scope, ScopeError};
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Client, Method, StatusCode, Url};
use tokio::sync::Semaphore;

use crate::Module;

/// Default request timeout.
pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 8_000;
/// Default concurrent follow-up fetches (robots / sitemap).
pub const DEFAULT_HTTP_CONCURRENCY: usize = 4;
/// Max redirects followed on the primary URL.
const MAX_REDIRECTS: usize = 5;
/// Synthetic Origin used for CORS probes.
const CORS_PROBE_ORIGIN: &str = "https://keld.invalid";

/// Configuration for one HTTP audit job.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub target: String,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dry_run: bool,
    pub rate_per_sec: Option<u32>,
}

impl HttpConfig {
    /// Build from CLI/TUI strings.
    pub fn from_parts(
        target: impl Into<String>,
        timeout_ms: u64,
        concurrency: usize,
        dry_run: bool,
        rate_per_sec: Option<u32>,
    ) -> Result<Self, HttpError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(HttpError::InvalidTarget {
                target,
                reason: "empty".into(),
            });
        }
        Ok(Self {
            target,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            concurrency: concurrency.max(1),
            dry_run,
            rate_per_sec,
        })
    }

    /// Short parameters line for audit / status.
    pub fn parameters_summary(&self) -> String {
        format!(
            "timeout_ms={} concurrency={} dry_run={} rate={}",
            self.timeout.as_millis(),
            self.concurrency,
            self.dry_run,
            self.rate_per_sec
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none".into()),
        )
    }
}

/// Finding severity for HTTP audit rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl HttpSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// One HTTP finding (or dry-run plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpFinding {
    pub url: String,
    pub severity: HttpSeverity,
    pub kind: String,
    pub detail: String,
    pub planned: bool,
}

impl HttpFinding {
    /// Compact summary used on the event bus and in TUI parsing.
    pub fn summary_line(&self) -> String {
        if self.planned {
            return format!(
                "would audit {} (headers+cookies+cors+fingerprint+robots+sitemap)",
                self.url
            );
        }
        format!(
            "sev={} url={} kind={} {}",
            self.severity.as_str(),
            self.url,
            self.kind,
            self.detail
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error("invalid target `{target}`: {reason}")]
    InvalidTarget { target: String, reason: String },
    #[error("http client: {0}")]
    Client(String),
}

/// HTTP audit module.
#[derive(Debug, Clone)]
pub struct HttpModule {
    pub config: HttpConfig,
    pub scope: Scope,
}

impl HttpModule {
    pub fn new(config: HttpConfig, scope: Scope) -> Self {
        Self { config, scope }
    }

    /// Scope-check, then audit the URL (or dry-run).
    pub async fn run_http(
        &self,
        job_id: JobId,
        events: EventSender,
    ) -> Result<Vec<HttpFinding>, HttpError> {
        let url = normalize_url(&self.config.target)?;
        let host = url
            .host_str()
            .ok_or_else(|| HttpError::InvalidTarget {
                target: self.config.target.clone(),
                reason: "missing host".into(),
            })?
            .to_string();
        self.scope.check(&host)?;

        if self.config.dry_run {
            return Ok(self.emit_dry_run(job_id, &events, &url).await);
        }

        let client = build_client(self.config.timeout)?;
        let mut rate = RateLimiter::per_second(self.config.rate_per_sec);
        let mut findings = Vec::new();
        let total = 4u64;

        rate.wait().await;
        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: 0,
            total,
            message: format!("GET {url}"),
        });

        let primary = fetch(&client, Method::GET, url.clone(), None).await;
        match &primary {
            Ok(resp) => {
                findings.extend(analyze_response(&url, resp, true));
            }
            Err(e) => {
                findings.push(finding(
                    url.as_str(),
                    HttpSeverity::High,
                    "connect",
                    e.clone(),
                ));
            }
        }
        publish_batch(
            job_id,
            &events,
            &findings[findings.len().saturating_sub(20)..],
        )
        .await;
        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: 1,
            total,
            message: "primary response audited".into(),
        });

        rate.wait().await;
        let cors_findings = match fetch(
            &client,
            Method::OPTIONS,
            url.clone(),
            Some(&[
                ("Origin", CORS_PROBE_ORIGIN),
                ("Access-Control-Request-Method", "GET"),
            ]),
        )
        .await
        {
            Ok(resp) => analyze_cors_options(&url, &resp),
            Err(e) => vec![finding(
                url.as_str(),
                HttpSeverity::Low,
                "cors",
                format!("OPTIONS probe failed: {e}"),
            )],
        };
        let cors_start = findings.len();
        findings.extend(cors_findings);
        publish_batch(job_id, &events, &findings[cors_start..]).await;
        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: 2,
            total,
            message: "CORS probe done".into(),
        });

        let robots_url = join_path(&url, "/robots.txt");
        let sitemap_url = join_path(&url, "/sitemap.xml");
        let sem = Arc::new(Semaphore::new(self.config.concurrency));
        let mut handles = Vec::new();

        for (label, fetch_url) in [
            ("robots", robots_url.clone()),
            ("sitemap", sitemap_url.clone()),
        ] {
            rate.wait().await;
            let permit = sem.clone().acquire_owned().await.expect("semaphore open");
            let client = client.clone();
            let label = label.to_string();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let result = fetch(&client, Method::GET, fetch_url.clone(), None).await;
                (label, fetch_url, result)
            }));
        }

        let mut step = 2u64;
        for handle in handles {
            match handle.await {
                Ok((label, fetch_url, result)) => {
                    let batch = match result {
                        Ok(resp) if label == "robots" => analyze_robots(&fetch_url, &resp),
                        Ok(resp) => analyze_sitemap(&fetch_url, &resp),
                        Err(e) => vec![finding(
                            fetch_url.as_str(),
                            HttpSeverity::Info,
                            &label,
                            format!("error: {e}"),
                        )],
                    };
                    publish_batch(job_id, &events, &batch).await;
                    findings.extend(batch);
                }
                Err(e) => {
                    let _ = events.publish(ModuleEvent::Log {
                        job_id,
                        level: keld_core::LogLevel::Warn,
                        message: format!("worker join: {e}"),
                    });
                }
            }
            step += 1;
            let _ = events.publish(ModuleEvent::Progress {
                job_id,
                done: step.min(total),
                total,
                message: "follow-up fetches".into(),
            });
        }

        let _ = events.publish(ModuleEvent::Done { job_id });
        Ok(findings)
    }

    async fn emit_dry_run(
        &self,
        job_id: JobId,
        events: &EventSender,
        url: &Url,
    ) -> Vec<HttpFinding> {
        let finding = HttpFinding {
            url: url.to_string(),
            severity: HttpSeverity::Info,
            kind: "planned".into(),
            detail: "headers+cookies+cors+fingerprint+robots+sitemap".into(),
            planned: true,
        };
        let summary = finding.summary_line();
        let _ = events.publish(ModuleEvent::Progress {
            job_id,
            done: 1,
            total: 1,
            message: summary.clone(),
        });
        let _ = events.publish(ModuleEvent::Result { job_id, summary });
        let _ = events.publish(ModuleEvent::Done { job_id });
        vec![finding]
    }
}

impl Module for HttpModule {
    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn run<'a>(
        &'a self,
        job_id: JobId,
        events: EventSender,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match self.run_http(job_id, events.clone()).await {
                Ok(_) => {}
                Err(e) => {
                    let _ = events.publish(ModuleEvent::Error {
                        job_id,
                        message: e.to_string(),
                    });
                }
            }
        })
    }
}

struct Fetched {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: String,
}

async fn publish_batch(job_id: JobId, events: &EventSender, batch: &[HttpFinding]) {
    for f in batch {
        let _ = events.publish(ModuleEvent::Result {
            job_id,
            summary: f.summary_line(),
        });
    }
}

fn build_client(timeout: Duration) -> Result<Client, HttpError> {
    Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(RedirectPolicy::limited(MAX_REDIRECTS))
        .user_agent("keld-http/0.1")
        .build()
        .map_err(|e| HttpError::Client(e.to_string()))
}

async fn fetch(
    client: &Client,
    method: Method,
    url: Url,
    extra: Option<&[(&str, &str)]>,
) -> Result<Fetched, String> {
    let mut req = client.request(method, url);
    if let Some(headers) = extra {
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            let val = v.to_str().ok()?.to_string();
            Some((k.as_str().to_string(), val))
        })
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 64_000 {
        body.chars().take(64_000).collect()
    } else {
        body
    };
    Ok(Fetched {
        status,
        headers,
        body,
    })
}

fn analyze_response(url: &Url, resp: &Fetched, include_cors_get: bool) -> Vec<HttpFinding> {
    let mut out = Vec::new();
    let u = url.as_str();
    let https = url.scheme().eq_ignore_ascii_case("https");

    out.push(finding(
        u,
        HttpSeverity::Info,
        "status",
        format!(
            "{} {}",
            resp.status.as_u16(),
            resp.status.canonical_reason().unwrap_or("")
        ),
    ));

    let header_map = |name: &str| -> Option<&str> {
        resp.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    let checks: &[(&str, HttpSeverity, bool)] = &[
        ("strict-transport-security", HttpSeverity::Medium, https),
        ("content-security-policy", HttpSeverity::Medium, true),
        ("x-content-type-options", HttpSeverity::Low, true),
        ("referrer-policy", HttpSeverity::Low, true),
        ("permissions-policy", HttpSeverity::Low, true),
    ];
    for (name, sev, applicable) in checks {
        if !applicable {
            continue;
        }
        match header_map(name) {
            Some(v) => out.push(finding(
                u,
                HttpSeverity::Info,
                "header",
                format!("{name}=present {}", sanitize(v, 120)),
            )),
            None => out.push(finding(u, *sev, "header", format!("{name}=missing"))),
        }
    }

    let xfo = header_map("x-frame-options");
    let csp = header_map("content-security-policy");
    let frame_ok = xfo.is_some()
        || csp
            .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
            .unwrap_or(false);
    if frame_ok {
        out.push(finding(
            u,
            HttpSeverity::Info,
            "header",
            format!(
                "clickjacking=present {}",
                sanitize(xfo.or(csp).unwrap_or(""), 80)
            ),
        ));
    } else {
        out.push(finding(
            u,
            HttpSeverity::Medium,
            "header",
            "clickjacking=missing (no X-Frame-Options / CSP frame-ancestors)".into(),
        ));
    }

    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            out.push(analyze_cookie(u, value, https));
        }
    }

    if include_cors_get {
        out.extend(analyze_cors_get(u, &resp.headers));
    }

    out.extend(fingerprint(u, &resp.headers, &resp.body));
    out
}

fn analyze_cookie(url: &str, raw: &str, https: bool) -> HttpFinding {
    let lower = raw.to_ascii_lowercase();
    let mut issues = Vec::new();
    if https && !lower.contains("; secure") && !lower.contains(";secure") {
        issues.push("missing Secure");
    }
    if !lower.contains("; httponly") && !lower.contains(";httponly") {
        issues.push("missing HttpOnly");
    }
    if !lower.contains("samesite=") {
        issues.push("missing SameSite");
    }
    let name = raw.split('=').next().unwrap_or("cookie");
    if issues.is_empty() {
        finding(
            url,
            HttpSeverity::Info,
            "cookie",
            format!("{name}=ok flags"),
        )
    } else {
        finding(
            url,
            HttpSeverity::Medium,
            "cookie",
            format!("{name} {}", issues.join("; ")),
        )
    }
}

fn analyze_cors_get(url: &str, headers: &[(String, String)]) -> Vec<HttpFinding> {
    let mut out = Vec::new();
    let acao = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
        .map(|(_, v)| v.as_str());
    let acac = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-credentials"))
        .map(|(_, v)| v.as_str());

    match acao {
        Some("*") => {
            let sev = if acac
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                HttpSeverity::High
            } else {
                HttpSeverity::Low
            };
            out.push(finding(
                url,
                sev,
                "cors",
                format!("ACAO=* credentials={}", acac.unwrap_or("absent")),
            ));
        }
        Some(v) => out.push(finding(
            url,
            HttpSeverity::Info,
            "cors",
            format!(
                "ACAO={} credentials={}",
                sanitize(v, 80),
                acac.unwrap_or("absent")
            ),
        )),
        None => out.push(finding(
            url,
            HttpSeverity::Info,
            "cors",
            "no Access-Control-Allow-Origin on GET".into(),
        )),
    }
    out
}

fn analyze_cors_options(url: &Url, resp: &Fetched) -> Vec<HttpFinding> {
    let u = url.as_str();
    let acao = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
        .map(|(_, v)| v.as_str());
    let acam = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-methods"))
        .map(|(_, v)| v.as_str());

    match acao {
        Some("*") => vec![finding(
            u,
            HttpSeverity::Medium,
            "cors",
            format!(
                "OPTIONS ACAO=* methods={} status={}",
                sanitize(acam.unwrap_or("-"), 60),
                resp.status.as_u16()
            ),
        )],
        Some(v) if v == CORS_PROBE_ORIGIN => vec![finding(
            u,
            HttpSeverity::Medium,
            "cors",
            format!(
                "OPTIONS reflects Origin methods={} status={}",
                sanitize(acam.unwrap_or("-"), 60),
                resp.status.as_u16()
            ),
        )],
        Some(v) => vec![finding(
            u,
            HttpSeverity::Info,
            "cors",
            format!(
                "OPTIONS ACAO={} methods={} status={}",
                sanitize(v, 60),
                sanitize(acam.unwrap_or("-"), 40),
                resp.status.as_u16()
            ),
        )],
        None => vec![finding(
            u,
            HttpSeverity::Info,
            "cors",
            format!("OPTIONS no ACAO status={}", resp.status.as_u16()),
        )],
    }
}

fn fingerprint(url: &str, headers: &[(String, String)], body: &str) -> Vec<HttpFinding> {
    let mut out = Vec::new();
    for name in ["server", "x-powered-by", "x-aspnet-version", "via"] {
        if let Some((_, v)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            out.push(finding(
                url,
                HttpSeverity::Info,
                "fingerprint",
                format!("{name}={}", sanitize(v, 100)),
            ));
        }
    }
    let lower = body.to_ascii_lowercase();
    for (needle, label) in [
        ("wp-content", "wordpress"),
        ("drupal.settings", "drupal"),
        ("__next", "nextjs"),
        ("csrfmiddlewaretoken", "django"),
        ("rails-env", "rails"),
    ] {
        if lower.contains(needle) {
            out.push(finding(
                url,
                HttpSeverity::Info,
                "fingerprint",
                format!("hint={label}"),
            ));
        }
    }
    if out.is_empty() {
        out.push(finding(
            url,
            HttpSeverity::Info,
            "fingerprint",
            "no strong signals".into(),
        ));
    }
    out
}

fn analyze_robots(url: &Url, resp: &Fetched) -> Vec<HttpFinding> {
    let u = url.as_str();
    if !resp.status.is_success() {
        return vec![finding(
            u,
            HttpSeverity::Info,
            "robots",
            format!("status={}", resp.status.as_u16()),
        )];
    }
    let disallow = resp
        .body
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("disallow:"))
        .count();
    let sitemaps = resp
        .body
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("sitemap:"))
        .count();
    vec![finding(
        u,
        HttpSeverity::Info,
        "robots",
        format!(
            "status={} disallow_rules={} sitemap_refs={} bytes={}",
            resp.status.as_u16(),
            disallow,
            sitemaps,
            resp.body.len()
        ),
    )]
}

fn analyze_sitemap(url: &Url, resp: &Fetched) -> Vec<HttpFinding> {
    let u = url.as_str();
    if !resp.status.is_success() {
        return vec![finding(
            u,
            HttpSeverity::Info,
            "sitemap",
            format!("status={}", resp.status.as_u16()),
        )];
    }
    let locs = resp.body.matches("<loc>").count();
    let is_index = resp.body.to_ascii_lowercase().contains("<sitemapindex");
    vec![finding(
        u,
        HttpSeverity::Info,
        "sitemap",
        format!(
            "status={} loc_entries={} index={} bytes={}",
            resp.status.as_u16(),
            locs,
            yes_no(is_index),
            resp.body.len()
        ),
    )]
}

fn finding(url: &str, severity: HttpSeverity, kind: &str, detail: String) -> HttpFinding {
    HttpFinding {
        url: url.to_string(),
        severity,
        kind: kind.to_string(),
        detail,
        planned: false,
    }
}

fn sanitize(s: &str, max: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() <= max {
        flat
    } else {
        flat.chars().take(max).collect::<String>() + "..."
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn normalize_url(raw: &str) -> Result<Url, HttpError> {
    let trimmed = raw.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    Url::parse(&with_scheme).map_err(|e| HttpError::InvalidTarget {
        target: raw.to_string(),
        reason: e.to_string(),
    })
}

fn join_path(base: &Url, path: &str) -> Url {
    let mut u = base.clone();
    u.set_path(path);
    u.set_query(None);
    u.set_fragment(None);
    u
}

/// Parse a Result summary back into an [`HttpFinding`] (TUI worker bridge).
pub fn parse_http_summary(summary: &str) -> Option<HttpFinding> {
    if let Some(rest) = summary.strip_prefix("would audit ") {
        let (url, _) = rest.split_once(" (")?;
        return Some(HttpFinding {
            url: url.to_string(),
            severity: HttpSeverity::Info,
            kind: "planned".into(),
            detail: "headers+cookies+cors+fingerprint+robots+sitemap".into(),
            planned: true,
        });
    }
    let rest = summary.strip_prefix("sev=")?;
    let (sev_s, rest) = rest.split_once(' ')?;
    let severity = HttpSeverity::parse(sev_s)?;
    let rest = rest.strip_prefix("url=")?;
    let (url, rest) = rest.split_once(" kind=")?;
    let (kind, detail) = rest.split_once(' ').unwrap_or((rest, ""));
    Some(HttpFinding {
        url: url.to_string(),
        severity,
        kind: kind.to_string(),
        detail: detail.to_string(),
        planned: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keld_core::{EventBus, Scope, ScopeEntry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn loopback_scope() -> Scope {
        Scope {
            includes: vec![
                ScopeEntry::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ScopeEntry::Host("localhost".into()),
            ],
            excludes: Vec::new(),
            notes: None,
            source: None,
        }
    }

    async fn spawn_http_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ =
                        tokio::time::timeout(Duration::from_millis(500), tcp.read(&mut buf)).await;
                    let req = String::from_utf8_lossy(&buf);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let method = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().next())
                        .unwrap_or("GET");

                    let (status, headers, body) = if path.starts_with("/robots.txt") {
                        (
                            "200 OK",
                            "Content-Type: text/plain\r\n",
                            "User-agent: *\nDisallow: /admin\nSitemap: http://127.0.0.1/sitemap.xml\n",
                        )
                    } else if path.starts_with("/sitemap.xml") {
                        (
                            "200 OK",
                            "Content-Type: application/xml\r\n",
                            "<?xml version=\"1.0\"?><urlset><url><loc>http://127.0.0.1/</loc></url></urlset>",
                        )
                    } else if method == "OPTIONS" {
                        (
                            "204 No Content",
                            "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\n",
                            "",
                        )
                    } else {
                        (
                            "200 OK",
                            "Server: keld-test\r\nX-Powered-By: testkit\r\nSet-Cookie: sid=1; Path=/\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/html\r\n",
                            "<html><body>wp-content ok</body></html>",
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                        body.len()
                    );
                    let _ = tcp.write_all(resp.as_bytes()).await;
                    let _ = tcp.shutdown().await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn dry_run_plans_without_connect() {
        let bus = EventBus::new(64);
        let cfg = HttpConfig::from_parts("http://127.0.0.1/", 200, 2, true, None).unwrap();
        let module = HttpModule::new(cfg, loopback_scope());
        let hits = module.run_http(JobId::new(1), bus.sender()).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].planned);
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let bus = EventBus::new(16);
        let cfg = HttpConfig::from_parts("https://8.8.8.8/", 200, 1, true, None).unwrap();
        let module = HttpModule::new(cfg, loopback_scope());
        let err = module
            .run_http(JobId::new(2), bus.sender())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            HttpError::Scope(ScopeError::OutOfScope { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audits_local_http_server() {
        let (addr, _server) = spawn_http_server().await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let url = format!("http://127.0.0.1:{}/", addr.port());
        let bus = EventBus::new(256);
        let cfg = HttpConfig::from_parts(&url, 2_000, 2, false, None).unwrap();
        let module = HttpModule::new(cfg, loopback_scope());
        let findings = module.run_http(JobId::new(3), bus.sender()).await.unwrap();

        assert!(findings.iter().any(|f| f.kind == "status"));
        assert!(findings
            .iter()
            .any(|f| f.kind == "header" && f.detail.contains("missing")));
        assert!(findings.iter().any(|f| f.kind == "cookie"));
        assert!(findings.iter().any(|f| f.kind == "cors"));
        assert!(findings
            .iter()
            .any(|f| f.kind == "fingerprint" && f.detail.contains("server=")));
        assert!(findings
            .iter()
            .any(|f| f.kind == "fingerprint" && f.detail.contains("wordpress")));
        assert!(findings.iter().any(|f| f.kind == "robots"));
        assert!(findings.iter().any(|f| f.kind == "sitemap"));
    }

    #[test]
    fn parse_roundtrip() {
        let f = HttpFinding {
            url: "https://example.com/".into(),
            severity: HttpSeverity::Medium,
            kind: "header".into(),
            detail: "content-security-policy=missing".into(),
            planned: false,
        };
        let parsed = parse_http_summary(&f.summary_line()).unwrap();
        assert_eq!(parsed, f);

        let plan = HttpFinding {
            url: "https://example.com/".into(),
            severity: HttpSeverity::Info,
            kind: "planned".into(),
            detail: "headers+cookies+cors+fingerprint+robots+sitemap".into(),
            planned: true,
        };
        assert_eq!(parse_http_summary(&plan.summary_line()).unwrap(), plan);
    }

    #[test]
    fn normalize_adds_https() {
        let u = normalize_url("example.com/path").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("example.com"));
    }
}

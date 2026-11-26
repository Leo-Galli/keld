//! Configuration: `keld.toml` < environment < CLI flags.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Theme name stored in config (TUI maps this to its theme id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemeName {
    #[default]
    Dark,
    Light,
    HighContrast,
}

impl ThemeName {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "high-contrast" | "highcontrast" | "hc" => Some(Self::HighContrast),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::HighContrast => "high-contrast",
        }
    }
}

/// Fully resolved runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub splash: bool,
    pub ascii: bool,
    pub no_color: bool,
    pub theme: ThemeName,
    /// Operator has accepted the authorized-use acknowledgement.
    pub authorized_ack: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            splash: true,
            ascii: false,
            no_color: false,
            theme: ThemeName::Dark,
            authorized_ack: false,
        }
    }
}

/// On-disk / partial layer (all fields optional so missing keys keep defaults).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConfigFile {
    pub splash: Option<bool>,
    pub ascii: Option<bool>,
    pub no_color: Option<bool>,
    pub theme: Option<ThemeName>,
    pub authorized_ack: Option<bool>,
}

impl ConfigFile {
    fn apply_to(&self, cfg: &mut Config) {
        if let Some(v) = self.splash {
            cfg.splash = v;
        }
        if let Some(v) = self.ascii {
            cfg.ascii = v;
        }
        if let Some(v) = self.no_color {
            cfg.no_color = v;
        }
        if let Some(v) = self.theme {
            cfg.theme = v;
        }
        if let Some(v) = self.authorized_ack {
            cfg.authorized_ack = v;
        }
    }

    fn from_config(cfg: &Config) -> Self {
        Self {
            splash: Some(cfg.splash),
            ascii: Some(cfg.ascii),
            no_color: Some(cfg.no_color),
            theme: Some(cfg.theme),
            authorized_ack: Some(cfg.authorized_ack),
        }
    }
}

/// CLI / programmatic overrides. `None` means "do not override this field".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigOverrides {
    pub config_path: Option<PathBuf>,
    pub no_splash: Option<bool>,
    pub ascii: Option<bool>,
    pub no_color: Option<bool>,
    pub theme: Option<ThemeName>,
}

/// Non-fatal load notes (missing or invalid file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarning {
    MissingFile { path: PathBuf },
    InvalidFile { path: PathBuf, message: String },
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFile { path } => {
                write!(f, "config not found at {}; using defaults", path.display())
            }
            Self::InvalidFile { path, message } => {
                write!(
                    f,
                    "invalid config at {}: {}; using defaults for file layer",
                    path.display(),
                    message
                )
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not determine a writable config directory")]
    NoConfigDir,
    #[error("serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Result of loading and merging config layers.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub warnings: Vec<ConfigWarning>,
    /// Path used for persistence (ack write). Always set.
    pub persist_path: PathBuf,
}

/// User-level config path: `$XDG_CONFIG_HOME/keld/keld.toml` (or OS equivalent).
pub fn user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("keld").join("keld.toml"))
}

/// Project-local config in the current working directory.
pub fn project_config_path() -> PathBuf {
    PathBuf::from("keld.toml")
}

/// Resolve which file to read: explicit path, else `./keld.toml`, else user config.
pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    let project = project_config_path();
    if project.is_file() {
        return project;
    }
    user_config_path().unwrap_or(project)
}

/// Path where acknowledgement and settings should be written.
pub fn persist_path(
    explicit: Option<&Path>,
    loaded_from: Option<&Path>,
) -> Result<PathBuf, ConfigError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = loaded_from {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }
    user_config_path().ok_or(ConfigError::NoConfigDir)
}

/// Load file + env + overrides. Missing/invalid file falls back to defaults with a warning.
pub fn load(overrides: &ConfigOverrides) -> LoadedConfig {
    let mut config = Config::default();
    let mut warnings = Vec::new();

    let path = resolve_config_path(overrides.config_path.as_deref());
    let mut loaded_from: Option<PathBuf> = None;

    match read_file(&path) {
        Ok(None) => {
            warnings.push(ConfigWarning::MissingFile { path: path.clone() });
        }
        Ok(Some(file)) => {
            file.apply_to(&mut config);
            loaded_from = Some(path.clone());
        }
        Err(msg) => {
            warnings.push(ConfigWarning::InvalidFile {
                path: path.clone(),
                message: msg,
            });
        }
    }

    apply_env(&mut config);
    apply_overrides(&mut config, overrides);

    let persist_path =
        persist_path(overrides.config_path.as_deref(), loaded_from.as_deref()).unwrap_or(path);

    LoadedConfig {
        config,
        warnings,
        persist_path,
    }
}

/// Merge layers for tests and callers that already have a file layer.
pub fn merge(file: Option<&ConfigFile>, env: &ConfigFile, flags: &ConfigOverrides) -> Config {
    let mut config = Config::default();
    if let Some(f) = file {
        f.apply_to(&mut config);
    }
    env.apply_to(&mut config);
    apply_overrides(&mut config, flags);
    config
}

/// Persist `authorized_ack = true`, preserving other known keys when the file exists.
pub fn persist_authorized_ack(path: &Path) -> Result<(), ConfigError> {
    let mut file = match read_file(path) {
        Ok(Some(f)) => f,
        Ok(None) => ConfigFile::default(),
        Err(_) => ConfigFile::default(),
    };
    file.authorized_ack = Some(true);

    // Fill defaults for a new file so the operator sees a complete template.
    if file.splash.is_none() {
        file.splash = Some(true);
    }
    if file.ascii.is_none() {
        file.ascii = Some(false);
    }
    if file.no_color.is_none() {
        file.no_color = Some(false);
    }
    if file.theme.is_none() {
        file.theme = Some(ThemeName::Dark);
    }

    write_file(path, &file)
}

/// Write a full config snapshot to disk.
pub fn save(path: &Path, config: &Config) -> Result<(), ConfigError> {
    write_file(path, &ConfigFile::from_config(config))
}

fn read_file(path: &Path) -> Result<Option<ConfigFile>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let file: ConfigFile = toml::from_str(&text).map_err(|e| e.to_string())?;
    Ok(Some(file))
}

fn write_file(path: &Path, file: &ConfigFile) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    let body = toml::to_string_pretty(file)?;
    fs::write(path, body).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn apply_env(config: &mut Config) {
    // Standard NO_COLOR (any value) forces no_color.
    if env::var_os("NO_COLOR").is_some() {
        config.no_color = true;
    }

    if let Ok(v) = env::var("KELD_NO_COLOR") {
        if let Some(b) = parse_bool(&v) {
            config.no_color = b;
        }
    }
    if let Ok(v) = env::var("KELD_ASCII") {
        if let Some(b) = parse_bool(&v) {
            config.ascii = b;
        }
    }
    if let Ok(v) = env::var("KELD_SPLASH") {
        if let Some(b) = parse_bool(&v) {
            config.splash = b;
        }
    }
    if let Ok(v) = env::var("KELD_NO_SPLASH") {
        if let Some(b) = parse_bool(&v) {
            if b {
                config.splash = false;
            }
        }
    }
    if let Ok(v) = env::var("KELD_THEME") {
        if let Some(t) = ThemeName::parse(&v) {
            config.theme = t;
        }
    }
    if let Ok(v) = env::var("KELD_AUTHORIZED_ACK") {
        if let Some(b) = parse_bool(&v) {
            config.authorized_ack = b;
        }
    }
}

fn apply_overrides(config: &mut Config, o: &ConfigOverrides) {
    if let Some(true) = o.no_splash {
        config.splash = false;
    }
    if let Some(v) = o.ascii {
        config.ascii = v;
    }
    if let Some(v) = o.no_color {
        config.no_color = v;
    }
    if let Some(v) = o.theme {
        config.theme = v;
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Snapshot of env-derived partial config (for unit tests of merge order).
pub fn env_layer_from_map(vars: &[(&str, &str)]) -> ConfigFile {
    let mut layer = ConfigFile::default();
    for &(key, value) in vars {
        match key {
            "NO_COLOR" => layer.no_color = Some(true),
            "KELD_NO_COLOR" => layer.no_color = parse_bool(value),
            "KELD_ASCII" => layer.ascii = parse_bool(value),
            "KELD_SPLASH" => layer.splash = parse_bool(value),
            "KELD_NO_SPLASH" => {
                if parse_bool(value) == Some(true) {
                    layer.splash = Some(false);
                }
            }
            "KELD_THEME" => layer.theme = ThemeName::parse(value),
            "KELD_AUTHORIZED_ACK" => layer.authorized_ack = parse_bool(value),
            _ => {}
        }
    }
    layer
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        env::temp_dir().join(format!("keld-config-{name}-{nanos}-{n}.toml"))
    }

    #[test]
    fn merge_precedence_file_env_flags() {
        let file = ConfigFile {
            splash: Some(true),
            ascii: Some(false),
            no_color: Some(false),
            theme: Some(ThemeName::Dark),
            authorized_ack: Some(false),
        };
        let env = env_layer_from_map(&[("KELD_ASCII", "true"), ("KELD_THEME", "light")]);
        let flags = ConfigOverrides {
            no_splash: Some(true),
            ascii: None,
            no_color: Some(true),
            theme: None,
            config_path: None,
        };

        let cfg = merge(Some(&file), &env, &flags);
        assert!(!cfg.splash, "flags override splash");
        assert!(cfg.ascii, "env overrides file ascii");
        assert!(cfg.no_color, "flags override no_color");
        assert_eq!(cfg.theme, ThemeName::Light, "env overrides theme");
        assert!(!cfg.authorized_ack);
    }

    #[test]
    fn flags_beat_env() {
        let env = env_layer_from_map(&[("KELD_ASCII", "false"), ("KELD_THEME", "light")]);
        let flags = ConfigOverrides {
            ascii: Some(true),
            theme: Some(ThemeName::HighContrast),
            ..Default::default()
        };
        let cfg = merge(None, &env, &flags);
        assert!(cfg.ascii);
        assert_eq!(cfg.theme, ThemeName::HighContrast);
    }

    #[test]
    fn missing_file_uses_defaults() {
        let path = temp_path("missing");
        let loaded = load(&ConfigOverrides {
            config_path: Some(path.clone()),
            ..Default::default()
        });
        // Env (e.g. NO_COLOR) may still apply; file layer is absent.
        assert!(loaded.config.splash);
        assert!(!loaded.config.ascii);
        assert_eq!(loaded.config.theme, ThemeName::Dark);
        assert!(!loaded.config.authorized_ack);
        assert!(matches!(
            loaded.warnings.as_slice(),
            [ConfigWarning::MissingFile { .. }]
        ));
        assert_eq!(loaded.persist_path, path);
    }

    #[test]
    fn invalid_file_falls_back_with_warning() {
        let path = temp_path("bad");
        fs::write(&path, "splash = [[[").unwrap();
        let loaded = load(&ConfigOverrides {
            config_path: Some(path.clone()),
            ..Default::default()
        });
        assert!(loaded.config.splash);
        assert!(!loaded.config.authorized_ack);
        assert!(matches!(
            loaded.warnings.as_slice(),
            [ConfigWarning::InvalidFile { .. }]
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_valid_file() {
        let path = temp_path("ok");
        fs::write(
            &path,
            r#"
splash = false
ascii = true
theme = "high-contrast"
authorized_ack = true
"#,
        )
        .unwrap();
        let loaded = load(&ConfigOverrides {
            config_path: Some(path.clone()),
            ..Default::default()
        });
        assert!(!loaded.config.splash);
        assert!(loaded.config.ascii);
        assert_eq!(loaded.config.theme, ThemeName::HighContrast);
        assert!(loaded.config.authorized_ack);
        assert!(loaded.warnings.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persist_authorized_ack_creates_file() {
        let path = temp_path("ack");
        persist_authorized_ack(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("authorized_ack = true"));
        let loaded = load(&ConfigOverrides {
            config_path: Some(path.clone()),
            ..Default::default()
        });
        assert!(loaded.config.authorized_ack);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn theme_name_parse() {
        assert_eq!(ThemeName::parse("DARK"), Some(ThemeName::Dark));
        assert_eq!(
            ThemeName::parse("high-contrast"),
            Some(ThemeName::HighContrast)
        );
        assert_eq!(ThemeName::parse("nope"), None);
    }
}

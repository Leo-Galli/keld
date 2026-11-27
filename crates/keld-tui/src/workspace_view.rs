//! Workspace screen: list / create / activate SQLite projects.

use std::path::PathBuf;

use keld_core::{
    default_audit_path, AuditLog, Finding, Scope, WorkspaceInfo, WorkspaceStats, WorkspaceStore,
    DEFAULT_SCOPE_FILE,
};
use keld_report::load_document;

/// Form field on the Workspace screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceField {
    Name,
    ScopeFile,
    FindingsFile,
}

impl WorkspaceField {
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::ScopeFile,
            Self::ScopeFile => Self::FindingsFile,
            Self::FindingsFile => Self::Name,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Name => Self::FindingsFile,
            Self::ScopeFile => Self::Name,
            Self::FindingsFile => Self::ScopeFile,
        }
    }
}

/// TUI state for the Workspace screen.
#[derive(Debug, Clone)]
pub struct WorkspaceView {
    pub root: PathBuf,
    pub name: String,
    pub scope_file: String,
    pub findings_file: String,
    pub field: WorkspaceField,
    pub editing: bool,
    pub list: Vec<WorkspaceInfo>,
    pub selected: usize,
    pub detail: Option<WorkspaceStats>,
    pub message: String,
}

impl Default for WorkspaceView {
    fn default() -> Self {
        let root = WorkspaceStore::default_root().unwrap_or_else(|_| PathBuf::from("workspaces"));
        Self {
            root,
            name: String::new(),
            scope_file: DEFAULT_SCOPE_FILE.into(),
            findings_file: "findings.json".into(),
            field: WorkspaceField::Name,
            editing: false,
            list: Vec::new(),
            selected: 0,
            detail: None,
            message: String::new(),
        }
    }
}

impl WorkspaceView {
    pub fn active_value_mut(&mut self) -> &mut String {
        match self.field {
            WorkspaceField::Name => &mut self.name,
            WorkspaceField::ScopeFile => &mut self.scope_file,
            WorkspaceField::FindingsFile => &mut self.findings_file,
        }
    }

    pub fn field_push(&mut self, c: char) {
        if !c.is_control() {
            self.active_value_mut().push(c);
        }
    }

    pub fn field_backspace(&mut self) {
        self.active_value_mut().pop();
    }

    pub fn next_field(&mut self) {
        self.field = self.field.next();
    }

    pub fn prev_field(&mut self) {
        self.field = self.field.prev();
    }

    pub fn select_next(&mut self) {
        if self.list.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.list.len() - 1);
        self.refresh_detail();
    }

    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.refresh_detail();
    }

    pub fn selected_name(&self) -> Option<&str> {
        self.list.get(self.selected).map(|w| w.name.as_str())
    }

    fn store(&self) -> Result<WorkspaceStore, String> {
        WorkspaceStore::open(self.root.clone()).map_err(|e| e.to_string())
    }

    /// Reload list from disk; keeps selection when possible.
    pub fn refresh(&mut self) {
        match self
            .store()
            .and_then(|s| s.list().map_err(|e| e.to_string()))
        {
            Ok(list) => {
                let prev = self.selected_name().map(str::to_string);
                self.list = list;
                if let Some(name) = prev {
                    if let Some(i) = self.list.iter().position(|w| w.name == name) {
                        self.selected = i;
                    } else {
                        self.selected = self.selected.min(self.list.len().saturating_sub(1));
                    }
                } else {
                    self.selected = 0;
                }
                self.refresh_detail();
                if self.message.is_empty() {
                    self.message = format!("{} workspace(s)", self.list.len());
                }
            }
            Err(e) => {
                self.message = e;
                self.list.clear();
                self.detail = None;
            }
        }
    }

    pub fn refresh_detail(&mut self) {
        let Some(name) = self.selected_name().map(str::to_string) else {
            self.detail = None;
            return;
        };
        match self
            .store()
            .and_then(|s| s.open_workspace(&name).map_err(|e| e.to_string()))
            .and_then(|ws| ws.stats().map_err(|e| e.to_string()))
        {
            Ok(stats) => self.detail = Some(stats),
            Err(e) => {
                self.detail = None;
                self.message = e;
            }
        }
    }

    pub fn create(&mut self) -> Result<(), String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("name is required".into());
        }
        let store = self.store()?;
        store.create(&name).map_err(|e| e.to_string())?;
        self.message = format!("created `{name}`");
        self.name.clear();
        self.refresh();
        if let Some(i) = self.list.iter().position(|w| w.name == name) {
            self.selected = i;
            self.refresh_detail();
        }
        Ok(())
    }

    pub fn delete_selected(&mut self) -> Result<(), String> {
        let name = self
            .selected_name()
            .ok_or_else(|| "no workspace selected".to_string())?
            .to_string();
        let store = self.store()?;
        store.delete(&name).map_err(|e| e.to_string())?;
        self.message = format!("deleted `{name}`");
        self.refresh();
        Ok(())
    }

    /// Activate selected workspace: returns (name, scope, findings, audit entries).
    pub fn activate_selected(
        &mut self,
    ) -> Result<(String, Scope, Vec<Finding>, Vec<keld_core::AuditEntry>), String> {
        let name = self
            .selected_name()
            .ok_or_else(|| "no workspace selected".to_string())?
            .to_string();
        let store = self.store()?;
        let ws = store.open_workspace(&name).map_err(|e| e.to_string())?;
        let scope = ws.load_scope().map_err(|e| e.to_string())?;
        let findings = ws.list_findings().map_err(|e| e.to_string())?;
        let audit = ws.list_audit().map_err(|e| e.to_string())?;
        self.message = format!("activated `{name}`");
        Ok((name, scope, findings, audit))
    }

    pub fn import_scope_selected(&mut self) -> Result<(), String> {
        let name = self
            .selected_name()
            .ok_or_else(|| "no workspace selected".to_string())?
            .to_string();
        let path = PathBuf::from(self.scope_file.trim());
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let store = self.store()?;
        let ws = store.open_workspace(&name).map_err(|e| e.to_string())?;
        let scope = ws.set_scope_toml(&text).map_err(|e| e.to_string())?;
        self.message = format!("scope set ({})", scope.summary());
        self.refresh();
        Ok(())
    }

    pub fn import_findings_selected(&mut self) -> Result<(), String> {
        let name = self
            .selected_name()
            .ok_or_else(|| "no workspace selected".to_string())?
            .to_string();
        let path = PathBuf::from(self.findings_file.trim());
        let doc = load_document(&path).map_err(|e| e.to_string())?;
        let store = self.store()?;
        let ws = store.open_workspace(&name).map_err(|e| e.to_string())?;
        ws.upsert_findings(&doc.findings)
            .map_err(|e| e.to_string())?;
        self.message = format!("imported {} finding(s)", doc.findings.len());
        self.refresh();
        Ok(())
    }

    pub fn import_audit_selected(&mut self) -> Result<(), String> {
        let name = self
            .selected_name()
            .ok_or_else(|| "no workspace selected".to_string())?
            .to_string();
        let path = default_audit_path();
        let log = AuditLog::load(&path).map_err(|e| e.to_string())?;
        let n = log.entries().len();
        let store = self.store()?;
        let ws = store.open_workspace(&name).map_err(|e| e.to_string())?;
        ws.append_audit_many(log.entries())
            .map_err(|e| e.to_string())?;
        self.message = format!("imported {n} audit entr(y/ies)");
        self.refresh();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static N: AtomicU64 = AtomicU64::new(0);

    fn temp_view() -> WorkspaceView {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("keld-ws-tui-{nanos}-{n}"));
        let _ = std::fs::remove_dir_all(&root);
        let mut v = WorkspaceView {
            root,
            ..WorkspaceView::default()
        };
        v.refresh();
        v
    }

    #[test]
    fn create_and_activate() {
        let mut v = temp_view();
        v.name = "alpha".into();
        v.create().unwrap();
        assert_eq!(v.list.len(), 1);
        let (name, scope, findings, audit) = v.activate_selected().unwrap();
        assert_eq!(name, "alpha");
        assert!(scope.is_empty());
        assert!(findings.is_empty());
        assert!(audit.is_empty());
    }
}

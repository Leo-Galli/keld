//! Feature modules for Keld.
//!
//! Each module will implement a shared async trait and emit progress/result
//! events. They never write to stdout/stderr.

/// Placeholder until KL-005 wires the module trait and event bus.
pub fn module_count() -> usize {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_has_no_modules_yet() {
        assert_eq!(module_count(), 0);
    }
}

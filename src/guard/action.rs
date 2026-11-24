//! Guard action vocabulary (ALLOW/LOG/MASK/BLOCK).
//!
//! Lives in the `guard` layer next to [`crate::guard::category`] so the
//! audit types have zero upward imports; `policy`
//! re-exports it unchanged.

use std::fmt;

/// Resulting policy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum GuardAction {
    /// Allow the content.
    Allow,
    /// Allow the content but log it (auditability).
    Log,
    /// Mask the content (PII path) and pass it on.
    Mask,
    /// Block the content.
    Block,
}

/// Human-readable action name (`Allow`, `Log`, `Mask`, `Block`).
///
/// # Examples
/// ```
/// use redactify::GuardAction;
/// assert_eq!(GuardAction::Block.to_string(), "Block");
/// assert_eq!(GuardAction::Allow.to_string(), "Allow");
/// ```
impl fmt::Display for GuardAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "Allow",
            Self::Log => "Log",
            Self::Mask => "Mask",
            Self::Block => "Block",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::GuardAction;

    #[test]
    fn display_spells_every_action() {
        let all = [
            (GuardAction::Allow, "Allow"),
            (GuardAction::Log, "Log"),
            (GuardAction::Mask, "Mask"),
            (GuardAction::Block, "Block"),
        ];
        for (action, label) in all {
            assert_eq!(action.to_string(), label);
        }
    }
}

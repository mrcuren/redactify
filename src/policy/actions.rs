//! Per-entity-type actions: what the policy does with each detected PII
//! type (see [`EntityAction`]).
//!
//! Every type defaults to [`EntityAction::Mask`], the behaviour of a policy
//! without entity actions, so an empty [`EntityActions`] changes nothing.
//! The other actions, in the order they apply:
//!
//! 1. [`EntityAction::Ignore`] removes the type from detection itself: its
//!    candidates are dropped before overlap resolution (they never hide an
//!    overlapping candidate of another type), so the type is neither
//!    reported, nor masked, nor counted, on every endpoint that detects
//!    under the policy (detect, redact, guard, sanitize, stream, vault).
//! 2. Relevance rules ([`super::RelevancePolicy`]) downgrade the
//!    contextually expected entities of the remaining types: a downgraded
//!    entity is reported and left in the text, whatever its action.
//! 3. The remaining entities drive the decision by action:
//!    [`EntityAction::Block`] blocks it (the rationale names the type
//!    labels, never a value), [`EntityAction::Log`] makes it at least
//!    `Log` and leaves the entity unmasked in the sanitized text, and
//!    [`EntityAction::Mask`] masks it.
//!
//! Guard signals (injection, secrets, ...) and their thresholds are not
//! affected: a signal that blocks still blocks, whatever the entity
//! actions. Detection-only operations without a decision (detect, redact,
//! JSON redact, vault) keep reporting and masking `Block` and `Log` types.

use crate::pii::EntityType;

/// What the policy does with entities of one type.
///
/// # Examples
/// ```
/// use redactify::policy::EntityAction;
///
/// assert_eq!("block".parse::<EntityAction>(), Ok(EntityAction::Block));
/// assert_eq!("LOG".parse::<EntityAction>(), Ok(EntityAction::Log));
/// assert_eq!(EntityAction::default(), EntityAction::Mask);
/// assert_eq!(EntityAction::Ignore.as_str(), "IGNORE");
/// assert!("drop".parse::<EntityAction>().is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
#[non_exhaustive]
pub enum EntityAction {
    /// Mask the entity in sanitized output (the default).
    #[default]
    Mask,
    /// Block the decision when the entity is found.
    Block,
    /// Report and count the entity, leave it unmasked; the decision is at
    /// least `Log`.
    Log,
    /// Do not detect the type at all.
    Ignore,
}

impl EntityAction {
    /// The canonical label (`"MASK"`, `"BLOCK"`, `"LOG"`, `"IGNORE"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mask => "MASK",
            Self::Block => "BLOCK",
            Self::Log => "LOG",
            Self::Ignore => "IGNORE",
        }
    }
}

impl std::fmt::Display for EntityAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse error for [`EntityAction`]: the input is not one of
/// mask, block, log, ignore (compared ASCII-case-insensitively). The
/// message does not echo the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("unknown entity action: expected mask | block | log | ignore")]
pub struct EntityActionParseError;

impl std::str::FromStr for EntityAction {
    type Err = EntityActionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        [Self::Mask, Self::Block, Self::Log, Self::Ignore]
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(s))
            .ok_or(EntityActionParseError)
    }
}

/// Per-entity-type actions of a [`Policy`](super::Policy). Empty by
/// default: every type is masked.
///
/// # Examples
/// ```
/// use redactify::policy::{EntityAction, EntityActions};
/// use redactify::EntityType;
///
/// let mut actions = EntityActions::default();
/// actions.set(EntityType::Tckn, EntityAction::Block);
/// actions.set(EntityType::Email, EntityAction::Log);
/// assert_eq!(actions.action_for(EntityType::Tckn), EntityAction::Block);
/// assert_eq!(actions.action_for(EntityType::Phone), EntityAction::Mask);
/// assert_eq!(actions.get(EntityType::Phone), None);
/// assert_eq!(actions.len(), 2);
/// ```
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntityActions {
    entries: Vec<(EntityType, EntityAction)>,
}

// Order-insensitive equality: the same action set built in another
// insertion order is the same policy (as for `CategoryOverrides`).
impl PartialEq for EntityActions {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.entries.iter().all(|(k, a)| other.get(*k) == Some(*a))
    }
}
impl Eq for EntityActions {}

impl EntityActions {
    /// Sets (or replaces) the action of one type.
    pub fn set(&mut self, kind: EntityType, action: EntityAction) {
        if let Some(slot) = self.entries.iter_mut().find(|(k, _)| *k == kind) {
            slot.1 = action;
        } else {
            self.entries.push((kind, action));
        }
    }

    /// The explicitly configured action of a type, if any.
    #[must_use]
    pub fn get(&self, kind: EntityType) -> Option<EntityAction> {
        self.entries
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, a)| *a)
    }

    /// The action that applies to a type: the configured one, else
    /// [`EntityAction::Mask`].
    #[must_use]
    pub fn action_for(&self, kind: EntityType) -> EntityAction {
        self.get(kind).unwrap_or_default()
    }

    /// The configured (type, action) pairs, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (EntityType, EntityAction)> + '_ {
        self.entries.iter().copied()
    }

    /// Number of configured types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no type has an action configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The types configured [`EntityAction::Ignore`] (the detector drops
    /// them before overlap resolution).
    pub(crate) fn ignored_types(&self) -> Vec<EntityType> {
        self.iter()
            .filter(|(_, a)| *a == EntityAction::Ignore)
            .map(|(k, _)| k)
            .collect()
    }

    /// Whether any type is configured [`EntityAction::Log`] (the masking
    /// pass then leaves those entities in the text).
    pub(crate) fn has_log(&self) -> bool {
        self.entries.iter().any(|(_, a)| *a == EntityAction::Log)
    }
}

/// How many entities of one type a decision found, and the action the
/// policy applied to them. Content-free: a type label, an action and a
/// count.
///
/// The count covers the raw text and its scan views: the raw and the
/// normalized view are two renderings of the same text (the larger of
/// their counts is taken), every decoded view (base64 layers, escapes) is
/// separate content and adds its own. Relevance-downgraded entities are
/// not counted (see [`Decision::relevance_downgraded`](super::Decision::relevance_downgraded)),
/// and [`EntityAction::Ignore`] types are never detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct EntityCount {
    /// The entity type.
    pub kind: EntityType,
    /// The action the policy applied to this type.
    pub action: EntityAction,
    /// How many entities of the type were found.
    pub count: usize,
}

/// Counts per type, in first-seen order, of entities found in up to three
/// groups (`max(a, b) + c` per type, see [`EntityCount`]); `Ignore` types
/// are dropped (defensive: the detector never reports them).
pub(crate) fn tally<'e>(
    raw: impl IntoIterator<Item = &'e crate::pii::Entity>,
    normalized: impl IntoIterator<Item = &'e crate::pii::Entity>,
    decoded: impl IntoIterator<Item = &'e crate::pii::Entity>,
    actions: &EntityActions,
) -> Vec<EntityCount> {
    // (type, raw, normalized, decoded)
    let mut rows: Vec<(EntityType, usize, usize, usize)> = Vec::new();
    let mut add = |kind: EntityType, group: usize| {
        let row = match rows.iter_mut().position(|r| r.0 == kind) {
            Some(i) => &mut rows[i],
            None => {
                rows.push((kind, 0, 0, 0));
                rows.last_mut().expect("just pushed")
            }
        };
        match group {
            0 => row.1 += 1,
            1 => row.2 += 1,
            _ => row.3 += 1,
        }
    };
    for e in raw {
        add(e.kind, 0);
    }
    for e in normalized {
        add(e.kind, 1);
    }
    for e in decoded {
        add(e.kind, 2);
    }
    rows.into_iter()
        .filter_map(|(kind, raw, norm, dec)| {
            let action = actions.action_for(kind);
            (action != EntityAction::Ignore).then_some(EntityCount {
                kind,
                action,
                count: raw.max(norm) + dec,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{tally, EntityAction, EntityActions};
    use crate::pii::{Entity, EntityType};

    fn ent(kind: EntityType) -> Entity {
        Entity {
            kind,
            start: 0,
            end: 1,
            text: String::new(),
            score: 1.0,
        }
    }

    #[test]
    fn equality_ignores_insertion_order() {
        let mut a = EntityActions::default();
        a.set(EntityType::Tckn, EntityAction::Block);
        a.set(EntityType::Email, EntityAction::Log);
        let mut b = EntityActions::default();
        b.set(EntityType::Email, EntityAction::Log);
        b.set(EntityType::Tckn, EntityAction::Block);
        assert_eq!(a, b);
        b.set(EntityType::Email, EntityAction::Ignore);
        assert_ne!(a, b);
        assert_eq!(b.len(), 2, "set replaces, never appends a duplicate");
    }

    #[test]
    fn tally_takes_the_larger_view_and_adds_decoded() {
        let mut actions = EntityActions::default();
        actions.set(EntityType::Email, EntityAction::Log);
        actions.set(EntityType::Phone, EntityAction::Ignore);
        let raw = [ent(EntityType::Tckn), ent(EntityType::Email)];
        let norm = [
            ent(EntityType::Tckn),
            ent(EntityType::Tckn),
            ent(EntityType::Phone),
        ];
        let dec = [ent(EntityType::Email)];
        let t = tally(&raw, &norm, &dec, &actions);
        let got: Vec<(EntityType, EntityAction, usize)> =
            t.iter().map(|c| (c.kind, c.action, c.count)).collect();
        assert_eq!(
            got,
            [
                (EntityType::Tckn, EntityAction::Mask, 2),
                (EntityType::Email, EntityAction::Log, 2),
            ]
        );
    }

    #[test]
    fn action_labels_round_trip() {
        for a in [
            EntityAction::Mask,
            EntityAction::Block,
            EntityAction::Log,
            EntityAction::Ignore,
        ] {
            assert_eq!(a.as_str().parse::<EntityAction>(), Ok(a));
            assert_eq!(a.as_str().to_ascii_lowercase().parse(), Ok(a));
            assert_eq!(a.to_string(), a.as_str());
        }
    }
}

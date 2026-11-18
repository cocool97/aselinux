//! Rule lookup state shared by the search tabs.

use crate::policy_index::{Direction, KindFilter, PolicyIndex, RuleHit, RuleQuery};

/// A value recomputed only when its key changes.
pub(crate) struct Cached<K, V> {
    key: Option<K>,
    value: V,
}

impl<K, V: Default> Default for Cached<K, V> {
    fn default() -> Self {
        Self {
            key: None,
            value: V::default(),
        }
    }
}

impl<K: PartialEq, V> Cached<K, V> {
    /// Recomputes the value if `key` changed; returns whether it did.
    pub(crate) fn update(&mut self, key: K, compute: impl FnOnce(&K) -> V) -> bool {
        if self.key.as_ref() == Some(&key) {
            return false;
        }
        self.value = compute(&key);
        self.key = Some(key);
        true
    }

    pub(crate) fn value(&self) -> &V {
        &self.value
    }

    /// Key of the current value, `None` until the first update.
    pub(crate) fn key(&self) -> Option<&K> {
        self.key.as_ref()
    }
}

/// Options of a rule lookup, as edited in the UI.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct QueryOptions {
    pub(crate) direction: Direction,
    pub(crate) kinds: KindFilter,
    /// Comma or space separated classes.
    pub(crate) classes: String,
    /// Comma or space separated permissions.
    pub(crate) perms: String,
    pub(crate) expand_subject: bool,
    pub(crate) expand_other: bool,
}

impl QueryOptions {
    pub(crate) fn new(direction: Direction) -> Self {
        Self {
            direction,
            kinds: KindFilter::default(),
            classes: String::new(),
            perms: String::new(),
            expand_subject: true,
            expand_other: false,
        }
    }

    /// Runs the lookup of `subject` with these options.
    pub(crate) fn run(&self, index: &PolicyIndex, subject: &str) -> Vec<RuleHit> {
        let classes = split_terms(&self.classes);
        let perms = split_terms(&self.perms);
        index.query(&RuleQuery {
            subject,
            direction: self.direction,
            expand_subject: self.expand_subject,
            expand_other: self.expand_other,
            kinds: self.kinds,
            classes: &classes,
            perms: &perms,
        })
    }
}

/// Key of cached rule lookups: project generation, subject and options.
pub(crate) type HitsKey = (u64, String, QueryOptions);

fn split_terms(s: &str) -> Vec<&str> {
    s.split([',', ' ']).filter(|w| !w.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::{Cached, split_terms};

    #[test]
    fn terms_are_split_on_commas_and_spaces() {
        assert_eq!(
            split_terms(" read,  write ,exec"),
            ["read", "write", "exec"]
        );
    }

    #[test]
    fn cache_recomputes_only_on_key_change() {
        let mut cache: Cached<u8, u32> = Cached::default();
        assert!(cache.update(1, |_| 10));
        assert!(!cache.update(1, |_| unreachable!()));
        assert!(cache.update(2, |_| 20));
        assert_eq!(*cache.value(), 20);
    }
}

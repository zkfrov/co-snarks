//! Triple-consumption profiler.
//!
//! Counts how many Beaver triples are consumed per "tag". Caller sets a tag
//! via [`set_tag`] (or the scoped [`TagGuard`]) and every call to
//! `next_triple`/`next_triple_batch` increments the counter for that tag.
//!
//! At the end of a proof, [`dump_sorted`] returns a histogram sorted by
//! consumption, which tells you which part of the circuit ate the triples.

use std::collections::HashMap;
use std::sync::Mutex;

static TAG: Mutex<String> = Mutex::new(String::new());
static COUNTERS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

fn ensure_init() {
    let mut g = COUNTERS.lock().unwrap();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
}

/// Set the current tag.
pub fn set_tag(tag: impl Into<String>) {
    *TAG.lock().unwrap() = tag.into();
}

/// Record `n` triples consumed under the current tag.
#[inline]
pub fn record_triples(n: usize) {
    if n == 0 {
        return;
    }
    ensure_init();
    let tag = TAG.lock().unwrap().clone();
    let mut g = COUNTERS.lock().unwrap();
    let map = g.as_mut().unwrap();
    *map.entry(tag).or_insert(0) += n;
}

/// Reset all counters and the current tag.
pub fn reset() {
    *TAG.lock().unwrap() = String::new();
    *COUNTERS.lock().unwrap() = Some(HashMap::new());
}

/// Returns (tag, count) sorted by count descending.
pub fn dump_sorted() -> Vec<(String, usize)> {
    let g = COUNTERS.lock().unwrap();
    let mut v: Vec<(String, usize)> = g
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect())
        .unwrap_or_default();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}

/// Scoped tag guard. Restores the previous tag on drop.
pub struct TagGuard {
    prev: String,
}

impl TagGuard {
    pub fn new(tag: impl Into<String>) -> Self {
        let mut cur = TAG.lock().unwrap();
        let prev = cur.clone();
        *cur = tag.into();
        Self { prev }
    }
}

impl Drop for TagGuard {
    fn drop(&mut self) {
        *TAG.lock().unwrap() = std::mem::take(&mut self.prev);
    }
}

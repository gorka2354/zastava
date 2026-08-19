//! Агрегаты по журналу для `zastava stats`.
//!
//! Ключевая цифра — доля повторов уже виденных сигнатур (суррогат M/N из
//! design-дока: «сколько промптов было бы» и какой потолок у policy-once).

use std::collections::{BTreeMap, BTreeSet};

use crate::record::CallRecord;

/// Сводка по журналу.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatsSummary {
    /// Всего вызовов.
    pub total: u64,
    /// Уникальных сигнатур (server, tool, canonical_subset).
    pub unique_sigs: u64,
    /// Вызовы, повторяющие уже виденную сигнатуру (M из M/N).
    pub repeats: u64,
    /// Вызовов на сервер.
    pub per_server: BTreeMap<String, u64>,
    /// Deny-вердиктов (включая warn-режим, где они не блокировали).
    pub denies: u64,
    /// Ошибочных вызовов (включая таймауты).
    pub errors: u64,
}

impl StatsSummary {
    /// Доля повторов, 0..=1. None, если вызовов не было.
    pub fn repeat_ratio(&self) -> Option<f64> {
        (self.total > 0).then(|| self.repeats as f64 / self.total as f64)
    }
}

/// Считает сводку за один проход по записям (порядок = порядок журнала).
pub fn summarize(records: &[CallRecord]) -> StatsSummary {
    let mut summary = StatsSummary::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for record in records {
        summary.total += 1;
        *summary.per_server.entry(record.server.clone()).or_default() += 1;
        if record.decision == "deny" {
            summary.denies += 1;
        }
        if record.is_error {
            summary.errors += 1;
        }
        let sig_key = format!(
            "{}\u{1f}{}\u{1f}{:?}\u{1f}{}",
            record.server, record.tool, record.canonical_subset, record.canon_version
        );
        if !seen.insert(sig_key) {
            summary.repeats += 1;
        }
    }

    summary.unique_sigs = seen.len() as u64;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn record(server: &str, tool: &str, decision: &str, is_error: bool) -> CallRecord {
        CallRecord {
            ts: String::new(),
            id: String::new(),
            server: server.into(),
            tool: tool.into(),
            canonical_subset: BTreeMap::new(),
            canon_version: 0,
            args_hash: String::new(),
            decision: decision.into(),
            enforced: false,
            matched_rule: None,
            duration_ms: 0,
            result_bytes: 0,
            is_error,
        }
    }

    #[test]
    fn counts_repeats_and_aggregates() {
        let records = vec![
            record("github", "create_issue", "allow", false),
            record("github", "create_issue", "allow", false), // повтор
            record("github", "search", "allow", false),
            record("qdrant", "search", "deny", false),
            record("github", "create_issue", "allow", true), // повтор + ошибка
        ];
        let s = summarize(&records);
        assert_eq!(s.total, 5);
        assert_eq!(s.unique_sigs, 3);
        assert_eq!(s.repeats, 2);
        assert_eq!(s.per_server["github"], 4);
        assert_eq!(s.per_server["qdrant"], 1);
        assert_eq!(s.denies, 1);
        assert_eq!(s.errors, 1);
        assert_eq!(s.repeat_ratio(), Some(0.4));
    }

    #[test]
    fn empty_log_gives_zeroes_and_no_ratio() {
        let s = summarize(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.repeat_ratio(), None);
    }
}

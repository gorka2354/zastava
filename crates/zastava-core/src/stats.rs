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
    /// Из них ФАКТИЧЕСКИ заблокировано. В warn-режиме — ноль, и разница
    /// между этими двумя числами обязана быть видна: пользователь, глядящий
    /// на «deny-вердиктов: 847», иначе считает, что его 847 раз прикрыли,
    /// тогда как не прикрыли ни разу (находка продуктового ревью M3).
    pub blocked: u64,
    /// Вызовы, записанные прошлыми поколениями канонизации. Смешивать их со
    /// свежими в подсчёте уникальности нельзя — иначе один и тот же вызов
    /// считается двумя разными сигнатурами.
    pub legacy_calls: u64,
    /// Строк журнала, которые не удалось прочитать. Побитый журнал не должен
    /// выглядеть как пустой.
    pub unreadable_lines: u64,
    /// Ошибочных вызовов (включая таймауты).
    pub errors: u64,
    /// Вызовов, брошенных по таймауту (побочный эффект мог состояться).
    pub abandoned: u64,
    /// Маркеров-событий гейтвея (старт, отключение аудита, ротация).
    pub markers: u64,
    /// Заметок `zastava annotate`: сколько раз человек оценил срабатывание.
    /// Единственная цифра здесь, которая приходит не от машины, — и потому
    /// единственная, по которой видно, приносит ли гейт пользу.
    pub annotations: u64,
    /// Ослаблений политики на живом reload (enforce -> warn, снятие правил).
    pub weakenings: u64,
    /// Сколько раз downstream-сервер оказывался недоступен: не поднялся или
    /// выпал из выдачи инструментов. Без этой строки его инструменты просто
    /// «исчезают», и человек ищет причину не там (находка ревью M2-full).
    pub unreachable: u64,
    /// Сколько раз downstream просил у пользователя то, что застава не
    /// пересылает (sampling / roots / elicitation). Попытка сервера
    /// обратиться к человеку — событие, о котором стоит знать.
    pub reverse_refused: u64,
    /// Уникальных сигнатур С УЧЁТОМ хэша аргументов. `canonical_subset`
    /// покрывает только ключи-идентификаторы, поэтому счёт по нему схлопывает
    /// вызовы, различающиеся остальными аргументами, и завышает выгоду
    /// policy-once — честный M/N лежит в диапазоне между двумя цифрами
    /// (находка верификации M1).
    pub unique_sigs_with_args: u64,
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
    let mut seen_with_args: BTreeSet<String> = BTreeSet::new();

    for record in records {
        if !record.is_call() {
            summary.markers += 1;
            match record.tool.as_str() {
                "annotation" => summary.annotations += 1,
                "policy_weakened" => summary.weakenings += 1,
                "downstream_failed" | "downstream_unreachable" => summary.unreachable += 1,
                "reverse_request_refused" => summary.reverse_refused += 1,
                _ => {}
            }
            continue;
        }
        summary.total += 1;
        if record.abandoned {
            summary.abandoned += 1;
        }
        *summary.per_server.entry(record.server.clone()).or_default() += 1;
        if record.decision == "deny" {
            summary.denies += 1;
            if record.enforced {
                summary.blocked += 1;
            }
        }
        if record.canon_version != crate::signature::CANON_VERSION {
            summary.legacy_calls += 1;
        }
        if record.is_error {
            summary.errors += 1;
        }
        // Версия канонизации в ключ НЕ входит: после апгрейда один и тот же
        // вызов считался бы двумя разными сигнатурами, а M/N — единственная
        // цифра, которой продукт доказывает пользу, — занижалась вдвое
        // (находка ревью M3). Факт смешения поколений виден отдельно.
        let sig_key = format!(
            "{}\u{1f}{}\u{1f}{:?}",
            record.server, record.tool, record.canonical_subset
        );
        seen_with_args.insert(format!("{sig_key}\u{1f}{}", record.args_hash));
        if !seen.insert(sig_key) {
            summary.repeats += 1;
        }
    }

    summary.unique_sigs = seen.len() as u64;
    summary.unique_sigs_with_args = seen_with_args.len() as u64;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(server: &str, tool: &str, decision: &str, is_error: bool) -> CallRecord {
        CallRecord {
            server: server.into(),
            tool: tool.into(),
            decision: decision.into(),
            is_error,
            ..Default::default()
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
    fn args_aware_uniqueness_is_reported_separately() {
        // Два вызова одного инструмента с РАЗНЫМИ аргументами: tool-level
        // счёт считает это повтором, args-aware — нет.
        let mut a = record("s", "t", "allow", false);
        a.args_hash = "aaa".into();
        let mut b = record("s", "t", "allow", false);
        b.args_hash = "bbb".into();
        let s = summarize(&[a, b]);
        assert_eq!(s.unique_sigs, 1);
        assert_eq!(s.unique_sigs_with_args, 2);
        assert_eq!(s.repeats, 1, "tool-level повтор остаётся повтором");
    }

    #[test]
    fn annotations_and_weakenings_are_counted_separately() {
        let records = vec![
            CallRecord::marker("t".into(), "1".into(), "annotation", Some("помогло".into())),
            CallRecord::marker("t".into(), "2".into(), "policy_weakened", None),
            CallRecord::marker("t".into(), "3".into(), "gateway_started", None),
            record("a", "ping", "allow", false),
        ];
        let s = summarize(&records);
        assert_eq!(s.annotations, 1);
        assert_eq!(s.weakenings, 1);
        assert_eq!(s.markers, 3);
        assert_eq!(s.total, 1);
    }

    #[test]
    fn markers_do_not_pollute_call_stats() {
        let records = vec![
            CallRecord::marker("t".into(), "id".into(), "audit_disabled", None),
            record("a", "ping", "allow", false),
        ];
        let s = summarize(&records);
        assert_eq!(s.total, 1, "маркер — не вызов");
        assert_eq!(s.markers, 1);
    }

    #[test]
    fn empty_log_gives_zeroes_and_no_ratio() {
        let s = summarize(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.repeat_ratio(), None);
    }
}

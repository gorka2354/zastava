//! `zastava learn` (bootstrap-версия M1): черновики правил из наблюдений.
//!
//! Человек, жмущий «allow не глядя», не станет писать YAML не глядя — правила
//! должны рождаться из журнала. M1 предлагает tool-level правила; M3 добавит
//! аргументные на базе canonical_subset.

use std::collections::BTreeSet;

use crate::config::{Config, NS_SEP};
use crate::policy::PolicyEngine;
use crate::record::CallRecord;

/// Результат генерации черновиков.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LearnOutput {
    /// Сигнатуры, встреченные в журнале и не покрытые текущими правилами.
    pub new_sigs: Vec<String>,
    /// Готовый TOML-блок для zastava.toml (юзер вычёркивает лишнее).
    pub toml_snippet: String,
    /// Готовый сниппет клиентского `permissions.allow` (per-tool, через заставу).
    pub client_allow_snippet: String,
    /// Сигнатуры, уже покрытые правилом с аргументными матчерами. НЕ попадают
    /// в черновик: tool-level правило поверх такого сняло бы осознанное
    /// сужение (например, «create_issue только в repo X»).
    pub narrowed: Vec<String>,
    /// Сигнатуры серверов, которых нет в этом конфиге. Журнал общий на
    /// машину, а конфиги проектные — предложить такое правило означало бы
    /// сломать конфиг (`unknown server`) при вставке.
    pub foreign: Vec<String>,
}

/// Строит черновики по журналу. Дедупликация — по (server, tool).
///
/// Три категории, и различать их обязательно (находка ревью M1, подтверждена
/// двумя независимыми ревьюерами): покрытое tool-level правилом молчит;
/// покрытое АРГУМЕНТНЫМ правилом уходит в `narrowed` (предложить поверх
/// tool-level = снять сужение); вызовы к серверам не из этого конфига уходят
/// в `foreign` (журнал общий на машину, конфиги проектные).
pub fn suggest(records: &[CallRecord], config: &Config) -> LearnOutput {
    let engine = PolicyEngine::from_config(&config.policy);
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut narrowed: BTreeSet<String> = BTreeSet::new();
    let mut foreign: BTreeSet<String> = BTreeSet::new();

    for record in records.iter().filter(|r| r.is_call()) {
        let sig = format!("{}{NS_SEP}{}", record.server, record.tool);
        if !config.servers.contains_key(&record.server) {
            foreign.insert(sig);
            continue;
        }
        match engine.covering_rule(&record.server, &record.tool) {
            Some((rule, true)) => {
                narrowed.insert(format!("{sig} (уже сужено правилом {rule})"));
            }
            Some((_, false)) => {}
            None => {
                seen.insert((record.server.clone(), record.tool.clone()));
            }
        }
    }

    let new_sigs: Vec<String> = seen
        .iter()
        .map(|(server, tool)| format!("{server}{NS_SEP}{tool}"))
        .collect();

    let toml_snippet = new_sigs
        .iter()
        .map(|sig| format!("[[policy.allow]]\nsig = \"{sig}\"\n"))
        .collect::<Vec<_>>()
        .join("\n");

    let client_allow_snippet = if new_sigs.is_empty() {
        String::new()
    } else {
        let rules = new_sigs
            .iter()
            .map(|sig| format!("    \"mcp__zastava{NS_SEP}{sig}\""))
            .collect::<Vec<_>>()
            .join(",\n");
        format!("\"permissions\": {{\n  \"allow\": [\n{rules}\n  ]\n}}")
    };

    LearnOutput {
        new_sigs,
        toml_snippet,
        client_allow_snippet,
        narrowed: narrowed.into_iter().collect(),
        foreign: foreign.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(server: &str, tool: &str) -> CallRecord {
        CallRecord {
            ts: "2026-08-19T12:00:00Z".into(),
            id: "e".into(),
            server: server.into(),
            tool: tool.into(),
            decision: "deny".into(),
            ..Default::default()
        }
    }

    #[test]
    fn suggests_uncovered_and_skips_covered() {
        let config = Config::from_toml_str(
            "[servers.github]\ncommand = \"x\"\n[servers.qdrant]\ncommand = \"y\"\n[[policy.allow]]\nsig = \"github__*\"\n",
        )
        .unwrap();
        let records = vec![
            record("github", "create_issue"), // покрыт wildcard-правилом
            record("qdrant", "search"),
            record("qdrant", "search"), // дубликат схлопывается
            record("qdrant", "upsert"),
        ];
        let out = suggest(&records, &config);
        assert_eq!(out.new_sigs, vec!["qdrant__search", "qdrant__upsert"]);
        assert!(out.toml_snippet.contains("sig = \"qdrant__search\""));
        assert!(!out.toml_snippet.contains("github"));
        assert!(out
            .client_allow_snippet
            .contains("mcp__zastava__qdrant__search"));
    }

    #[test]
    fn never_suggests_rule_that_widens_an_argument_rule() {
        // Находка ревью M1 (обе линзы независимо): tool-level предложение
        // поверх правила с args сняло бы сужение по repo.
        let config = Config::from_toml_str(
            "[servers.github]\ncommand = \"x\"\n[[policy.allow]]\nsig = \"github__create_issue\"\nargs = { repo = \"safe/repo\" }\n",
        )
        .unwrap();
        let out = suggest(&[record("github", "create_issue")], &config);
        assert!(
            out.new_sigs.is_empty(),
            "предлагать tool-level поверх аргументного правила нельзя: {:?}",
            out.new_sigs
        );
        assert_eq!(out.narrowed.len(), 1);
        assert!(out.narrowed[0].contains("github__create_issue"));
    }

    #[test]
    fn foreign_servers_are_reported_not_suggested() {
        // Журнал общий на машину: сервер другого проекта не должен попадать
        // в черновик, иначе вставка ломает конфиг (unknown server).
        let config = Config::from_toml_str("[servers.a]\ncommand = \"x\"\n").unwrap();
        let out = suggest(&[record("qdrant", "search"), record("a", "ping")], &config);
        assert_eq!(out.new_sigs, vec!["a__ping"]);
        assert_eq!(out.foreign, vec!["qdrant__search"]);
    }

    #[test]
    fn markers_are_skipped() {
        let config = Config::from_toml_str("[servers.a]\ncommand = \"x\"\n").unwrap();
        let marker = CallRecord::marker("t".into(), "id".into(), "audit_disabled", None);
        let out = suggest(&[marker], &config);
        assert!(out.new_sigs.is_empty());
    }

    #[test]
    fn empty_log_yields_empty_output() {
        let config = Config::from_toml_str("[servers.a]\ncommand = \"x\"\n").unwrap();
        let out = suggest(&[], &config);
        assert!(out.new_sigs.is_empty());
        assert!(out.toml_snippet.is_empty());
        assert!(out.client_allow_snippet.is_empty());
    }
}

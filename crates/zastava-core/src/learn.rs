//! `zastava learn` (bootstrap-версия M1): черновики правил из наблюдений.
//!
//! Человек, жмущий «allow не глядя», не станет писать YAML не глядя — правила
//! должны рождаться из журнала. M1 предлагает tool-level правила; M3 добавит
//! аргументные на базе canonical_subset.

use std::collections::BTreeSet;

use crate::config::{Config, NS_SEP};
use crate::policy::{PolicyEngine, Verdict};
use crate::record::CallRecord;

/// Результат генерации черновиков.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnOutput {
    /// Сигнатуры, встреченные в журнале и не покрытые текущими правилами.
    pub new_sigs: Vec<String>,
    /// Готовый TOML-блок для zastava.toml (юзер вычёркивает лишнее).
    pub toml_snippet: String,
    /// Готовый сниппет клиентского `permissions.allow` (per-tool, через заставу).
    pub client_allow_snippet: String,
}

/// Строит черновики по журналу. Дедупликация — по (server, tool); покрытое
/// существующими правилами не предлагается повторно.
pub fn suggest(records: &[CallRecord], config: &Config) -> LearnOutput {
    let engine = PolicyEngine::from_config(&config.policy);
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();

    for record in records {
        // tool-level проверка покрытия: аргументы правил здесь не учитываем —
        // learn v0 предлагает только tool-level правила.
        let covered = matches!(
            engine
                .decide(&record.server, &record.tool, &serde_json::Map::new())
                .verdict,
            Verdict::Allow
        );
        if !covered {
            seen.insert((record.server.clone(), record.tool.clone()));
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn record(server: &str, tool: &str) -> CallRecord {
        CallRecord {
            ts: "2026-08-19T12:00:00Z".into(),
            id: "e".into(),
            server: server.into(),
            tool: tool.into(),
            canonical_subset: BTreeMap::new(),
            canon_version: 0,
            args_hash: String::new(),
            decision: "deny".into(),
            enforced: false,
            matched_rule: None,
            duration_ms: 0,
            result_bytes: 0,
            is_error: false,
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
    fn empty_log_yields_empty_output() {
        let config = Config::from_toml_str("[servers.a]\ncommand = \"x\"\n").unwrap();
        let out = suggest(&[], &config);
        assert!(out.new_sigs.is_empty());
        assert!(out.toml_snippet.is_empty());
        assert!(out.client_allow_snippet.is_empty());
    }
}

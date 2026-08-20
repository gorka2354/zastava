//! Канонизация аргументов: что из вызова безопасно писать в журнал открыто.
//!
//! Это ядро M3 и вся его продуктовая ценность держится на одном балансе:
//! - **аргументные правила** («github можно, но только в repo X») невозможны,
//!   пока `learn` не видит аргументов;
//! - **писать аргументы целиком нельзя** — там токены и содержимое файлов.
//!
//! Развязка — whitelist КЛЮЧЕЙ-ИДЕНТИФИКАТОРОВ (fail-closed: не «всё, кроме
//! подозрительного», а «только явно разрешённое»), плюс нормализация значений
//! (путь усекается до нескольких компонентов, URL — до схемы и хоста) и отказ
//! от значений, похожих на секрет по длине и энтропии.
//!
//! Всё остальное в журнал не попадает вовсе — от него остаётся только
//! `args_hash`. Правила канонизации версионируются (`CANON_VERSION`): один и
//! тот же журнал не должен давать разные сигнатуры после смены правил.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::config::{CanonConfig, NS_SEP};

/// Ключи аргументов, значения которых считаются идентификаторами ресурса, а
/// не данными. Список намеренно короткий и скучный: расширять его — решение
/// пользователя (`[canon] extra_keys`), а не наша догадка.
pub const DEFAULT_ID_KEYS: &[&str] = &[
    "repo",
    "repository",
    "owner",
    "org",
    "project",
    "path",
    "file_path",
    "directory",
    "collection",
    "database",
    "table",
    "index",
    "bucket",
    "namespace",
    "channel",
    "host",
    "url",
    "uri",
    "branch",
    "workspace",
];

/// Максимальная длина канонизированного значения. Длиннее — это уже данные,
/// а не идентификатор.
const MAX_VALUE_LEN: usize = 96;
/// Сколько компонентов пути оставляем: «C:/work/proj/src/deep/file.rs» →
/// «C:/work/proj». Достаточно, чтобы правило значило «в этом проекте», и мало,
/// чтобы журнал не превращался в карту файловой системы.
const PATH_COMPONENTS: usize = 3;

/// Скомпилированные правила канонизации.
#[derive(Debug, Clone)]
pub struct CanonRules {
    global_keys: BTreeSet<String>,
    denied_keys: BTreeSet<String>,
    /// Полная сигнатура `<server>__<tool>` → набор ключей для неё.
    per_tool: BTreeMap<String, BTreeSet<String>>,
}

impl Default for CanonRules {
    fn default() -> Self {
        Self {
            global_keys: DEFAULT_ID_KEYS.iter().map(|k| k.to_string()).collect(),
            denied_keys: BTreeSet::new(),
            per_tool: BTreeMap::new(),
        }
    }
}

impl CanonRules {
    /// Строит правила из конфига поверх дефолтного whitelist.
    pub fn from_config(config: &CanonConfig) -> Self {
        let mut rules = Self::default();
        rules.global_keys.extend(config.extra_keys.iter().cloned());
        rules.denied_keys = config.deny_keys.iter().cloned().collect();
        for rule in &config.rules {
            rules
                .per_tool
                .insert(rule.sig.clone(), rule.keys.iter().cloned().collect());
        }
        rules
    }

    /// Какие ключи учитывать для конкретного инструмента.
    fn keys_for(&self, server: &str, tool: &str) -> &BTreeSet<String> {
        let sig = format!("{server}{NS_SEP}{tool}");
        self.per_tool.get(&sig).unwrap_or(&self.global_keys)
    }

    /// Канонический поднабор аргументов вызова.
    ///
    /// Пустой результат — нормальная и частая ситуация: он означает
    /// tool-level сигнатуру, то есть «различать вызовы по аргументам мы
    /// здесь не умеем», а не «аргументов не было».
    pub fn subset(
        &self,
        server: &str,
        tool: &str,
        args: &Map<String, Value>,
    ) -> BTreeMap<String, String> {
        let keys = self.keys_for(server, tool);
        let mut subset = BTreeMap::new();
        for (key, value) in args {
            if !keys.contains(key) || self.denied_keys.contains(key) {
                continue;
            }
            // Только строки: числа и объекты — это почти всегда данные, а
            // не адрес ресурса, и различать по ним вызовы смысла нет.
            let Value::String(raw) = value else { continue };
            if let Some(normalized) = normalize_value(key, raw) {
                subset.insert(key.clone(), normalized);
            }
        }
        subset
    }
}

/// Нормализует значение-идентификатор или отвергает его (`None`), если оно
/// не похоже на идентификатор: слишком длинное, многострочное или похожее на
/// секрет по энтропии.
fn normalize_value(key: &str, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\n') || trimmed.contains('\r') {
        return None;
    }
    if looks_like_secret(trimmed) {
        return None;
    }

    let normalized = if key.contains("url") || key.contains("uri") {
        normalize_url(trimmed)
    } else if is_pathish(key) {
        normalize_path(trimmed)
    } else {
        trimmed.to_string()
    };

    if normalized.chars().count() > MAX_VALUE_LEN {
        return None;
    }
    Some(normalized)
}

fn is_pathish(key: &str) -> bool {
    key.contains("path") || key == "directory" || key == "file"
}

/// Путь усекается до первых компонентов: правило должно значить «в этом
/// проекте», а журнал не должен становиться картой файловой системы.
fn normalize_path(raw: &str) -> String {
    let unified = raw.replace('\\', "/");
    let mut out = String::new();
    let mut taken = 0;
    for (index, part) in unified.split('/').enumerate() {
        // Ведущий пустой компонент у абсолютных unix-путей сохраняем.
        if part.is_empty() && index == 0 {
            continue;
        }
        if part.is_empty() {
            continue;
        }
        if taken == PATH_COMPONENTS {
            out.push_str("/…");
            break;
        }
        if index == 0 && !unified.starts_with('/') {
            out.push_str(part);
        } else {
            out.push('/');
            out.push_str(part);
        }
        taken += 1;
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        out
    }
}

/// URL сводится к схеме и хосту: путь и query — это уже данные запроса.
fn normalize_url(raw: &str) -> String {
    match raw.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            format!("{scheme}://{host}")
        }
        None => raw.split(['/', '?', '#']).next().unwrap_or(raw).to_string(),
    }
}

/// Грубая проверка «похоже на секрет»: длинная строка без структуры и с
/// высоким разнообразием символов. Лучше отвергнуть настоящий идентификатор
/// (правило просто станет tool-level), чем записать в журнал токен.
fn looks_like_secret(value: &str) -> bool {
    const SECRET_MIN_LEN: usize = 24;
    if value.len() < SECRET_MIN_LEN {
        return false;
    }
    // Путь или URL со структурой — не секрет, даже если длинный.
    if value.contains('/') || value.contains('\\') || value.contains(' ') {
        return false;
    }
    let distinct: BTreeSet<char> = value.chars().collect();
    let alnum = value.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    let mixed_case = value.chars().any(|c| c.is_ascii_uppercase())
        && value.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    // Длинная «каша» из букв разного регистра и цифр без разделителей —
    // типичный токен/хэш.
    alnum * 10 >= value.len() * 9 && distinct.len() >= 12 && mixed_case && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn args(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn only_whitelisted_keys_reach_the_journal() {
        let rules = CanonRules::default();
        let subset = rules.subset(
            "github",
            "create_issue",
            &args(&[
                ("repo", "gorka2354/zastava"),
                ("title", "секретный заголовок задачи"),
                ("body", "текст, который в журнал попадать не должен"),
            ]),
        );
        assert_eq!(subset.len(), 1, "{subset:?}");
        assert_eq!(subset["repo"], "gorka2354/zastava");
    }

    #[test]
    fn paths_are_truncated_to_a_few_components() {
        let rules = CanonRules::default();
        let subset = rules.subset(
            "fs",
            "read_file",
            &args(&[("path", "C:/work/secret-project/src/deep/nested/file.rs")]),
        );
        assert_eq!(subset["path"], "C:/work/secret-project/…");
    }

    #[test]
    fn unix_absolute_paths_keep_their_root() {
        let rules = CanonRules::default();
        let subset = rules.subset("fs", "read_file", &args(&[("path", "/home/alice/proj/a/b")]));
        assert_eq!(subset["path"], "/home/alice/proj/…");
    }

    #[test]
    fn urls_are_reduced_to_scheme_and_host() {
        let rules = CanonRules::default();
        let subset = rules.subset(
            "http",
            "fetch",
            &args(&[("url", "https://api.example.com/v1/users?token=abc")]),
        );
        assert_eq!(subset["url"], "https://api.example.com");
    }

    #[test]
    fn token_shaped_values_are_refused_even_on_allowed_keys() {
        let rules = CanonRules::default();
        let subset = rules.subset(
            "svc",
            "call",
            &args(&[("project", "ghp7Xk92LmQ4vTz8RaBn31YcWd05EfGh")]),
        );
        assert!(
            subset.is_empty(),
            "значение-токен не должно попасть в журнал: {subset:?}"
        );
    }

    #[test]
    fn non_string_and_multiline_values_are_skipped() {
        let rules = CanonRules::default();
        let mut raw = Map::new();
        raw.insert("repo".into(), Value::Bool(true));
        raw.insert("path".into(), Value::String("a\nb".into()));
        assert!(rules.subset("s", "t", &raw).is_empty());
    }

    #[test]
    fn per_tool_rules_override_the_global_whitelist() {
        let config = Config::from_toml_str(
            "[servers.qdrant]\ncommand = \"x\"\n\n[[canon.rules]]\nsig = \"qdrant__search\"\nkeys = [\"collection\"]\n",
        )
        .unwrap();
        let rules = CanonRules::from_config(&config.canon);
        let call = args(&[("collection", "notes"), ("repo", "should-be-ignored")]);
        let subset = rules.subset("qdrant", "search", &call);
        assert_eq!(subset.len(), 1);
        assert_eq!(subset["collection"], "notes");
        // Для другого инструмента действует общий whitelist.
        let other = rules.subset("qdrant", "upsert", &call);
        assert!(other.contains_key("repo"), "{other:?}");
    }

    #[test]
    fn deny_keys_win_over_the_whitelist() {
        let config = Config::from_toml_str(
            "[servers.a]\ncommand = \"x\"\n\n[canon]\ndeny_keys = [\"path\"]\n",
        )
        .unwrap();
        let rules = CanonRules::from_config(&config.canon);
        let subset = rules.subset("a", "t", &args(&[("path", "/tmp/x"), ("repo", "o/r")]));
        assert!(!subset.contains_key("path"), "{subset:?}");
        assert!(subset.contains_key("repo"));
    }

    #[test]
    fn extra_keys_extend_the_whitelist() {
        let config = Config::from_toml_str(
            "[servers.a]\ncommand = \"x\"\n\n[canon]\nextra_keys = [\"room\"]\n",
        )
        .unwrap();
        let rules = CanonRules::from_config(&config.canon);
        let subset = rules.subset("a", "t", &args(&[("room", "general")]));
        assert_eq!(subset["room"], "general");
    }
}

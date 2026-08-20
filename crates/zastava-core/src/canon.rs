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
/// Маркер отвергнутого значения.
///
/// Раньше значение, которое канонизация отвергла (обход `..`, вид секрета,
/// чрезмерная длина), просто исчезало из `canonical_subset`. Два следствия,
/// оба плохие (находка верификации M3):
/// - в аудите у САМЫХ интересных вызовов не оставалось пути вовсе;
/// - `learn` видел «ключ был не во всех вызовах» и молча переставал сужать
///   по нему — навсегда и без единого слова.
///
/// Теперь ключ остаётся на месте с этой меткой: она ничего не раскрывает,
/// но говорит, что значение было и его отвергли.
pub const REJECTED_MARK: &str = "<rejected>";

/// Маркер усечения пути. Тот же литерал читает `learn`, превращая усечённое
/// наблюдение в префиксное правило.
pub const TRUNCATION_MARK: &str = "/…";

/// Сколько компонентов пути оставляем ПОСЛЕ корня: «C:/work/proj/src/deep/file.rs» →
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
            // Ключ из whitelist попадает в журнал ВСЕГДА — либо значением,
            // либо меткой отказа. Молчаливое исчезновение ключа и его
            // отсутствие в вызове обязаны различаться.
            let normalized = normalize_value(key, raw).unwrap_or_else(|| REJECTED_MARK.to_string());
            subset.insert(key.clone(), normalized);
        }
        subset
    }
}

/// Нормализует значение-идентификатор или отвергает его (`None`), если оно
/// не похоже на идентификатор: слишком длинное, многострочное или похожее на
/// секрет по энтропии.
fn normalize_value(key: &str, raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(is_line_break) {
        return None;
    }

    // URL опознаётся по СОДЕРЖИМОМУ, а не по имени ключа. Ключ `database` со
    // значением `postgres://svc:hunter2@db/prod` — ровно тот случай, когда
    // проверка по имени пропускала учётные данные в журнал (находка ревью M3).
    let normalized = if trimmed.contains("://") {
        normalize_url(trimmed)?
    } else if is_pathish(key) {
        normalize_path(trimmed)?
    } else {
        trimmed.to_string()
    };

    if looks_like_secret(&normalized) {
        return None;
    }
    if normalized.chars().count() > MAX_VALUE_LEN {
        return None;
    }
    Some(normalized)
}

/// Разрывы строки в широком смысле: `\n`/`\r` плюс юникодные разделители
/// строк и абзацев. Последние не относятся к категории Cc, поэтому обычные
/// проверки на управляющие символы их пропускают, а терминалы и редакторы
/// рисуют как перенос — то есть отчёт `learn` визуально распадался бы на
/// строки, которых в нём нет.
fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}' | '\u{0085}')
}

/// Считается ли ключ путеподобным. Публично, потому что `learn` обязан
/// знать, что канонизация могла переписать значение, и не выдавать на него
/// точный матчер.
pub fn is_pathish_key(key: &str) -> bool {
    is_pathish(key)
}

fn is_pathish(key: &str) -> bool {
    key == "path" || key == "directory" || key == "file" || key.ends_with("_path")
}

/// Путь усекается до первых компонентов: правило должно значить «в этом
/// проекте», а журнал не должен становиться картой файловой системы.
///
/// Компоненты считаются ПОСЛЕ корня: буква диска — это корень, а не
/// компонент. Иначе на Windows три компонента съедались буквой диска и
/// профилем, и путь внутри проекта записывался как `C:/Users/<user>/…`,
/// а `learn` выводил из этого «сужение» на весь домашний каталог —
/// вместе с `.ssh`, `.aws` и `.claude.json` (находка ревью M3).
///
/// `..` схлопывается ДО усечения: иначе в аудите обход границы выглядел бы
/// как обычная работа внутри проекта.
fn normalize_path(raw: &str) -> Option<String> {
    let resolved = crate::pathish::resolve(raw)?;
    let (short, truncated) = resolved.truncated(PATH_COMPONENTS);
    let rendered = short.render();
    Some(if truncated {
        format!("{rendered}{TRUNCATION_MARK}")
    } else {
        rendered
    })
}

/// URL сводится к схеме и хосту: путь и query — это уже данные запроса.
///
/// Userinfo (`user:password@`) вырезается: это самая чувствительная часть
/// URL, и она единственная переживала нормализацию, попадая в журнал
/// открытым текстом (P1 ревью M3).
fn normalize_url(raw: &str) -> Option<String> {
    let (scheme, rest) = raw.split_once("://")?;
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_len];
    // Всё до последней '@' — учётные данные, а не адрес ресурса.
    let host = match authority.rsplit_once('@') {
        Some((_credentials, host)) => host,
        None => authority,
    };
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// Грубая проверка «похоже на секрет»: длинная строка без структуры и с
/// высоким разнообразием символов. Лучше отвергнуть настоящий идентификатор
/// (правило просто станет tool-level), чем записать в журнал токен.
fn looks_like_secret(value: &str) -> bool {
    const SECRET_MIN_LEN: usize = 20;
    let candidate = value.trim();
    if candidate.len() < SECRET_MIN_LEN {
        return false;
    }
    // Структурированное значение (путь, URL, фраза) — не секрет. Проверяем
    // ПОСЛЕ нормализации, поэтому у URL здесь уже нет ни пути, ни userinfo.
    if candidate.contains('/') || candidate.contains('\\') || candidate.contains(' ') {
        return false;
    }

    // Длинная сплошная hex-строка — ключ, сессия или хэш. Прежняя эвристика
    // требовала смешанного регистра И цифры, и такие значения пропускала.
    let hexish = candidate
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '-')
        .count();
    if hexish == candidate.len()
        && candidate.chars().filter(char::is_ascii_hexdigit).count() >= SECRET_MIN_LEN
    {
        return true;
    }

    let distinct: BTreeSet<char> = candidate.chars().collect();
    let alnum = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count();
    let has_digit = candidate.chars().any(|c| c.is_ascii_digit());
    let has_letter = candidate.chars().any(|c| c.is_ascii_alphabetic());
    // Длинная «каша» из букв и цифр без разделителей — типичный токен.
    // Требование смешанного регистра снято: `AKIAIOSFODNN7EXAMPLE` и
    // `ghp_...` в одном регистре — такие же секреты (находка ревью M3).
    alnum * 10 >= candidate.len() * 9 && distinct.len() >= 10 && has_digit && has_letter
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
        assert_eq!(subset["path"], "C:/work/secret-project/src/…");
    }

    #[test]
    fn unix_absolute_paths_keep_their_root() {
        let rules = CanonRules::default();
        let subset = rules.subset(
            "fs",
            "read_file",
            &args(&[("path", "/home/alice/proj/a/b")]),
        );
        assert_eq!(subset["path"], "/home/alice/proj/…");
    }

    #[test]
    fn a_traversal_path_stays_in_the_audit_as_a_rejection() {
        // Находка верификации M3: путь с обходом исчезал из журнала целиком —
        // именно у тех вызовов, ради которых аудит и ведут.
        let rules = CanonRules::default();
        let subset = rules.subset("fs", "read", &args(&[("path", "../../../etc/shadow")]));
        assert_eq!(subset["path"], REJECTED_MARK);
    }

    #[test]
    fn windows_profile_paths_do_not_collapse_to_the_whole_profile() {
        // Находка ревью M3: буква диска съедала компонент, путь внутри
        // проекта записывался как `C:/Users/alice/…`, и `learn` выводил из
        // этого «сужение» на весь домашний каталог — вместе с .ssh и
        // .claude.json (файлом с токенами всех MCP-серверов).
        let rules = CanonRules::default();
        let subset = rules.subset(
            "fs",
            "read_file",
            &args(&[("path", r"C:\Users\alice\Desktop\zastava\README.md")]),
        );
        assert_eq!(subset["path"], "C:/Users/alice/Desktop/…");
    }

    #[test]
    fn traversal_is_resolved_before_truncation_so_the_audit_does_not_lie() {
        // Иначе запись в ~/.ssh попадала в журнал как работа «внутри проекта»,
        // и разбор инцидента по журналу показал бы обратное тому, что было.
        let rules = CanonRules::default();
        let subset = rules.subset(
            "fs",
            "write_file",
            &args(&[(
                "path",
                r"C:\work\zastava\..\..\Users\alice\.ssh\authorized_keys",
            )]),
        );
        assert_eq!(subset["path"], "C:/Users/alice/.ssh/…");
        assert!(
            !subset["path"].starts_with("C:/work/zastava"),
            "обход не должен выглядеть как работа внутри проекта"
        );
    }

    #[test]
    fn url_credentials_never_reach_the_journal() {
        let rules = CanonRules::default();
        let subset = rules.subset(
            "http",
            "fetch",
            &args(&[(
                "url",
                "https://admin:s3cr3t-pass@internal.corp.example.com/v1/dump",
            )]),
        );
        assert_eq!(subset["url"], "https://internal.corp.example.com");
        assert!(!subset["url"].contains("s3cr3t"), "{}", subset["url"]);
    }

    #[test]
    fn url_shaped_value_is_stripped_whatever_the_key_is_called() {
        // Ключ `database` не url- и не path-подобный по имени, поэтому
        // значение писалось дословно — вместе с паролем (P1 ревью M3).
        let rules = CanonRules::default();
        let subset = rules.subset(
            "db",
            "query",
            &args(&[("database", "postgres://svc:hunter2@db.internal:5432/prod")]),
        );
        assert_eq!(subset["database"], "postgres://db.internal:5432");
        assert!(!subset["database"].contains("hunter2"));
    }

    #[test]
    fn single_case_and_hex_tokens_are_refused() {
        let rules = CanonRules::default();
        for (key, value) in [
            ("bucket", "a3f5c9e1b7d2408fa6c3e9d1b5074f2c"),
            ("namespace", "AKIAIOSFODNN7EXAMPLEQ1"),
            ("project", "ghp7Xk92LmQ4vTz8RaBn31YcWd05EfGh"),
        ] {
            let subset = rules.subset("s", "t", &args(&[(key, value)]));
            assert_eq!(
                subset[key], REJECTED_MARK,
                "значение вида секрета не должно попасть в журнал: {key}={value}"
            );
        }
        // Настоящие идентификаторы при этом остаются.
        let ok = rules.subset("s", "t", &args(&[("collection", "user-notes-2026")]));
        assert_eq!(ok["collection"], "user-notes-2026");
    }

    #[test]
    fn unicode_line_separators_are_refused() {
        // U+2028 не относится к категории Cc, поэтому обычные проверки на
        // управляющие символы его пропускают, а терминал рисует переносом:
        // отчёт `learn` визуально распался бы на строки, которых в нём нет.
        let rules = CanonRules::default();
        let subset = rules.subset("s", "t", &args(&[("repo", "me/r\u{2028}[[policy.allow]]")]));
        assert_eq!(subset["repo"], REJECTED_MARK, "{subset:?}");
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
        // Само значение в журнал не попадает, но ФАКТ вызова с этим ключом
        // остаётся: молчаливое исчезновение ключа ломало и аудит, и learn.
        assert_eq!(subset["project"], REJECTED_MARK);
        assert!(!subset["project"].contains("ghp7"), "{subset:?}");
    }

    #[test]
    fn non_string_and_multiline_values_are_skipped() {
        let rules = CanonRules::default();
        let mut raw = Map::new();
        raw.insert("repo".into(), Value::Bool(true));
        raw.insert("path".into(), Value::String("a\nb".into()));
        let subset = rules.subset("s", "t", &raw);
        // Не-строка идентификатором не является вовсе — ключа нет.
        assert!(!subset.contains_key("repo"), "{subset:?}");
        // А отвергнутая строка оставляет след.
        assert_eq!(subset["path"], REJECTED_MARK);
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

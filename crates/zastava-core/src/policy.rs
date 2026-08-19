//! PolicyEngine v0: единый движок с M1 (решение ревью 5A).
//!
//! Формат правил уже несёт аргументные матчеры; v0 реализует tool-level
//! матчинг и точное совпадение аргументов-строк. M3 расширяет матчеры
//! (префиксы, канонизация), не меняя формат конфига.
//!
//! Дефолтный режим — warn (пост-спайк): tool-level гейтинг делегирован
//! клиентскому `permissions.allow`, enforce включается осознанно.

use serde_json::{Map, Value};

use crate::config::{parse_sig, DefaultAction, PolicyConfig, PolicyMode};

/// Итог применения политики к вызову.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Что политика решила по сути вызова.
    pub verdict: Verdict,
    /// Блокирует ли решение вызов фактически (mode == enforce).
    /// В warn-режиме deny-вердикт только логируется.
    pub enforced: bool,
    /// Сигнатура правила, которое сработало (None — применён default).
    pub matched_rule: Option<String>,
}

/// Вердикт по вызову.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Вызов разрешён (правилом или default = allow).
    Allow,
    /// Вызов не покрыт правилами при default = deny.
    Deny,
}

impl Decision {
    /// Должен ли прокси реально заблокировать вызов.
    pub fn blocks(&self) -> bool {
        self.enforced && self.verdict == Verdict::Deny
    }
}

/// Скомпилированное правило (конфиг уже прошёл валидацию).
#[derive(Debug, Clone)]
struct CompiledRule {
    server: String,
    /// Имя инструмента или `*`.
    tool: String,
    /// Точные совпадения аргументов (v0). Пустая карта = совпадений не требуем.
    args: Vec<(String, String)>,
    /// Исходная сигнатура для журнала и сообщений.
    raw: String,
}

/// Движок политик. Создаётся из валидированного конфига; `decide` — чистая
/// функция без IO, безопасна для вызова на hot path.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    mode: PolicyMode,
    default: DefaultAction,
    rules: Vec<CompiledRule>,
}

impl PolicyEngine {
    /// Компилирует правила. Некорректные сигнатуры молча пропускаются —
    /// до этой точки их обязана была отсечь `Config::validate` (fail-closed
    /// на границе, а не паника в глубине).
    pub fn from_config(policy: &PolicyConfig) -> Self {
        let rules = policy
            .allow
            .iter()
            .filter_map(|rule| {
                let sig = parse_sig(&rule.sig)?;
                Some(CompiledRule {
                    server: sig.server.to_string(),
                    tool: sig.tool.to_string(),
                    args: rule
                        .args
                        .as_ref()
                        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        .unwrap_or_default(),
                    raw: rule.sig.clone(),
                })
            })
            .collect();
        Self {
            mode: policy.mode,
            default: policy.default,
            rules,
        }
    }

    /// Текущий режим движка.
    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// Есть ли правило, покрывающее пару (server, tool) на tool-уровне —
    /// БЕЗ учёта аргументных матчеров. Нужно `learn`: правило с матчером
    /// аргументов означает осознанное сужение, и предлагать поверх него
    /// tool-level правило нельзя — это молча сняло бы ограничение.
    /// Возвращает сигнатуру найденного правила и наличие у него матчеров.
    pub fn covering_rule(&self, server: &str, tool: &str) -> Option<(&str, bool)> {
        self.rules
            .iter()
            .find(|rule| rule.server == server && (rule.tool == "*" || rule.tool == tool))
            .map(|rule| (rule.raw.as_str(), !rule.args.is_empty()))
    }

    /// Решение по вызову инструмента `server`/`tool` с аргументами `args`.
    pub fn decide(&self, server: &str, tool: &str, args: &Map<String, Value>) -> Decision {
        let matched = self.rules.iter().find(|rule| {
            rule.server == server
                && (rule.tool == "*" || rule.tool == tool)
                && rule
                    .args
                    .iter()
                    .all(|(key, expected)| matches!(args.get(key), Some(Value::String(actual)) if actual == expected))
        });

        let (verdict, matched_rule) = match matched {
            Some(rule) => (Verdict::Allow, Some(rule.raw.clone())),
            None => match self.default {
                DefaultAction::Allow => (Verdict::Allow, None),
                DefaultAction::Deny => (Verdict::Deny, None),
            },
        };

        Decision {
            verdict,
            enforced: self.mode == PolicyMode::Enforce,
            matched_rule,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn engine(toml: &str) -> PolicyEngine {
        let config = Config::from_toml_str(toml).expect("test config must be valid");
        PolicyEngine::from_config(&config.policy)
    }

    fn args(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    const BASE: &str = r#"
[servers.github]
command = "npx"

[policy]
mode = "enforce"
default = "deny"

[[policy.allow]]
sig = "github__*"
"#;

    #[test]
    fn wildcard_rule_allows_any_tool_of_server() {
        let e = engine(BASE);
        let d = e.decide("github", "create_issue", &Map::new());
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.matched_rule.as_deref(), Some("github__*"));
        assert!(!d.blocks());
    }

    #[test]
    fn unknown_server_hits_default_deny_and_blocks_in_enforce() {
        let e = engine(BASE);
        let d = e.decide("qdrant", "search", &Map::new());
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.enforced);
        assert!(d.blocks());
        assert!(d.matched_rule.is_none());
    }

    #[test]
    fn warn_mode_never_blocks_even_on_deny() {
        let toml = "[servers.a]\ncommand = \"x\"\n[policy]\nmode = \"warn\"\n";
        let d = engine(toml).decide("a", "tool", &Map::new());
        assert_eq!(d.verdict, Verdict::Deny, "default deny остаётся вердиктом");
        assert!(!d.blocks(), "но warn-режим не блокирует");
    }

    #[test]
    fn args_matcher_requires_exact_string_match() {
        let toml = r#"
[servers.github]
command = "npx"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "github__create_issue"
args = { repo = "gorka2354/zastava" }
"#;
        let e = engine(toml);
        let ok = e.decide(
            "github",
            "create_issue",
            &args(&[("repo", "gorka2354/zastava")]),
        );
        assert_eq!(ok.verdict, Verdict::Allow);

        let wrong_value = e.decide("github", "create_issue", &args(&[("repo", "evil/repo")]));
        assert!(wrong_value.blocks(), "чужой repo должен блокироваться");

        let missing_arg = e.decide("github", "create_issue", &Map::new());
        assert!(missing_arg.blocks(), "отсутствующий аргумент = не матч");

        let non_string = {
            let mut m = Map::new();
            m.insert("repo".into(), Value::Bool(true));
            e.decide("github", "create_issue", &m)
        };
        assert!(
            non_string.blocks(),
            "не-строка не матчится точным матчером v0"
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let toml = r#"
[servers.a]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "a__ping"
[[policy.allow]]
sig = "a__*"
"#;
        let d = engine(toml).decide("a", "ping", &Map::new());
        assert_eq!(d.matched_rule.as_deref(), Some("a__ping"));
    }

    #[test]
    fn covering_rule_ignores_args_matchers() {
        let toml = r#"
[servers.github]
command = "npx"
[[policy.allow]]
sig = "github__create_issue"
args = { repo = "safe/repo" }
"#;
        let e = engine(toml);
        let (sig, narrowed) = e
            .covering_rule("github", "create_issue")
            .expect("правило с матчером всё равно считается покрывающим");
        assert_eq!(sig, "github__create_issue");
        assert!(narrowed, "и помечается как суженное аргументами");
        assert!(e.covering_rule("github", "other").is_none());
    }

    #[test]
    fn default_allow_lets_uncovered_through() {
        let toml =
            "[servers.a]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\ndefault = \"allow\"\n";
        let d = engine(toml).decide("a", "anything", &Map::new());
        assert_eq!(d.verdict, Verdict::Allow);
        assert!(!d.blocks());
    }
}

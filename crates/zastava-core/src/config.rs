//! Модель `zastava.toml`.
//!
//! Формат с первого дня рассчитан на аргументные матчеры (M3): правило несёт
//! текстовую сигнатуру `<server>__<tool>` / `<server>__*` и опциональную
//! таблицу `args` (в v0 парсится и валидируется, семантика включается в M3).
//! Разделитель неймспейса — `__`, поэтому имена серверов не могут его
//! содержать (иначе сигнатуры становятся неоднозначными).

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::ConfigError;

/// Разделитель неймспейса между сервером и инструментом.
pub const NS_SEP: &str = "__";

/// Корень конфига (`zastava.toml`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Downstream MCP-серверы, которые застава агрегирует.
    /// `default`, чтобы отсутствие секции ловилось доменной валидацией
    /// с внятным сообщением, а не сухим serde «missing field».
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
    /// Политики доступа к инструментам.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Настройки журнала вызовов.
    #[serde(default)]
    pub log: LogConfig,
    /// Настройки самого гейтвея (таймауты).
    #[serde(default)]
    pub proxy: ProxyConfig,
}

/// Секция `[proxy]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Таймаут одного downstream-вызова, мс. Зависший downstream не должен
    /// вешать весь гейтвей (контракт падения, решение 2A).
    #[serde(default = "default_call_timeout_ms")]
    pub call_timeout_ms: u64,
    /// Таймаут initialize-хендшейка с downstream при старте, мс.
    #[serde(default = "default_initialize_timeout_ms")]
    pub initialize_timeout_ms: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            call_timeout_ms: default_call_timeout_ms(),
            initialize_timeout_ms: default_initialize_timeout_ms(),
        }
    }
}

fn default_call_timeout_ms() -> u64 {
    60_000
}

fn default_initialize_timeout_ms() -> u64 {
    15_000
}

/// Один downstream-сервер (stdio; url-транспорт — вне v0.1).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Исполняемый файл (на Windows npx-серверы запускаются через `cmd /c` —
    /// этим занимается proxy-слой, в конфиге пишется как в клиентах).
    pub command: String,
    /// Аргументы команды.
    #[serde(default)]
    pub args: Vec<String>,
    /// Переменные окружения процесса.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Рабочая директория процесса.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Режим применения политик.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Логировать срабатывания, но не блокировать. Дефолт до M3:
    /// tool-level гейтинг делегирован клиентскому `permissions.allow`
    /// (вердикт спайка), enforce включается с аргументными правилами.
    #[default]
    Warn,
    /// Блокировать вызовы, не покрытые allow-правилами.
    Enforce,
}

/// Действие по умолчанию для вызова, не покрытого ни одним правилом.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    /// Deny-by-default — security-питч проекта.
    #[default]
    Deny,
    /// Разрешать непокрытое (осознанный опт-аут).
    Allow,
}

/// Секция `[policy]`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Режим: warn (дефолт) | enforce.
    #[serde(default)]
    pub mode: PolicyMode,
    /// Действие для непокрытых вызовов: deny (дефолт) | allow.
    #[serde(default)]
    pub default: DefaultAction,
    /// Allow-правила.
    #[serde(default)]
    pub allow: Vec<RuleConfig>,
}

/// Одно allow-правило.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Сигнатура: `<server>__<tool>` или `<server>__*`.
    pub sig: String,
    /// Аргументные матчеры (M3): ключ аргумента → точное значение.
    /// В v0 валидируются синтаксически, семантика — warn-заглушка.
    #[serde(default)]
    pub args: Option<BTreeMap<String, String>>,
}

/// Секция `[log]`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Путь к JSONL-журналу; по умолчанию — рядом с данными приложения
    /// (резолвится в cli-слое, core путей не выдумывает).
    #[serde(default)]
    pub path: Option<String>,
    /// Писать полные аргументы вызовов (off by default: до маскировки M4
    /// в журнал попадают только canonical_subset и хэш).
    #[serde(default)]
    pub log_args: bool,
}

/// Разобранная сигнатура правила.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSig<'a> {
    /// Имя downstream-сервера.
    pub server: &'a str,
    /// Имя инструмента или `*` (все инструменты сервера).
    pub tool: &'a str,
}

impl Config {
    /// Разбирает и валидирует конфиг из TOML-строки. Fail-closed: любая
    /// проблема — ошибка целиком, частично применённых конфигов не бывает.
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Доменная валидация поверх успешного разбора. Копит все проблемы.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();

        if self.servers.is_empty() {
            problems.push("no servers configured: [servers.<name>] is required".to_string());
        }
        for (name, server) in &self.servers {
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                problems.push(format!(
                    "server name '{name}' is invalid: use only [A-Za-z0-9_-]"
                ));
            }
            if name.contains(NS_SEP) {
                problems.push(format!(
                    "server name '{name}' must not contain '{NS_SEP}' (namespace separator)"
                ));
            }
            if server.command.trim().is_empty() {
                problems.push(format!("server '{name}': command is empty"));
            }
        }

        for rule in &self.policy.allow {
            match parse_sig(&rule.sig) {
                Some(sig) => {
                    if !self.servers.contains_key(sig.server) {
                        problems.push(format!(
                            "rule '{}' references unknown server '{}'",
                            rule.sig, sig.server
                        ));
                    }
                    if let Some(args) = &rule.args {
                        if sig.tool == "*" {
                            problems.push(format!(
                                "rule '{}': args matchers require a concrete tool, not '*'",
                                rule.sig
                            ));
                        }
                        for (key, value) in args {
                            if key.is_empty() {
                                problems
                                    .push(format!("rule '{}': empty args key", rule.sig));
                            }
                            if value.is_empty() {
                                problems.push(format!(
                                    "rule '{}': args['{key}'] is empty",
                                    rule.sig
                                ));
                            }
                        }
                    }
                }
                None => problems.push(format!(
                    "rule '{}' is malformed: expected '<server>{NS_SEP}<tool>' or '<server>{NS_SEP}*'",
                    rule.sig
                )),
            }
        }

        if self.proxy.call_timeout_ms == 0 {
            problems.push("proxy.call_timeout_ms must be > 0".to_string());
        }
        if self.proxy.initialize_timeout_ms == 0 {
            problems.push("proxy.initialize_timeout_ms must be > 0".to_string());
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems))
        }
    }
}

/// Разбирает текстовую сигнатуру правила. Сплит по ПЕРВОМУ `__`: имя
/// инструмента справа может содержать `__` (инструменты downstream'ов этого
/// не запрещают), имя сервера — нет (валидируется отдельно).
pub fn parse_sig(sig: &str) -> Option<RuleSig<'_>> {
    let (server, tool) = sig.split_once(NS_SEP)?;
    if server.is_empty() || tool.is_empty() {
        return None;
    }
    if server.contains('*') {
        return None;
    }
    if tool != "*" && tool.contains('*') {
        return None;
    }
    Some(RuleSig { server, tool })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
[servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[servers.shotik]
command = "node"
args = ["C:/path/to/shotik/mcp/index.js"]
env = { SHOTIK_MODE = "mcp" }

[policy]
mode = "warn"
default = "deny"

[[policy.allow]]
sig = "github__*"

[[policy.allow]]
sig = "github__create_issue"
args = { repo = "gorka2354/zastava" }

[log]
log_args = false
"#;

    #[test]
    fn full_example_parses() {
        let config = Config::from_toml_str(FULL).expect("full example must parse");
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.policy.mode, PolicyMode::Warn);
        assert_eq!(config.policy.default, DefaultAction::Deny);
        assert_eq!(config.policy.allow.len(), 2);
        let rule = &config.policy.allow[1];
        assert_eq!(rule.args.as_ref().unwrap()["repo"], "gorka2354/zastava");
        assert!(!config.log.log_args);
    }

    #[test]
    fn defaults_are_warn_and_deny() {
        let config =
            Config::from_toml_str("[servers.a]\ncommand = \"x\"\n").expect("minimal config");
        assert_eq!(config.policy.mode, PolicyMode::Warn);
        assert_eq!(config.policy.default, DefaultAction::Deny);
        assert!(config.policy.allow.is_empty());
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let err = Config::from_toml_str("[servers.a]\ncommand = \"x\"\n[extra]\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got: {err}");
    }

    #[test]
    fn unknown_server_field_is_rejected() {
        let err = Config::from_toml_str("[servers.a]\ncommand = \"x\"\nttl = 5\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got: {err}");
    }

    #[test]
    fn empty_servers_is_invalid() {
        let err = Config::from_toml_str("[policy]\nmode = \"warn\"\n").unwrap_err();
        assert_invalid_contains(&err, "no servers configured");
    }

    #[test]
    fn server_name_with_separator_is_invalid() {
        let err = Config::from_toml_str("[servers.a__b]\ncommand = \"x\"\n").unwrap_err();
        assert_invalid_contains(&err, "must not contain '__'");
    }

    #[test]
    fn rule_without_separator_is_invalid() {
        let toml = "[servers.a]\ncommand = \"x\"\n[[policy.allow]]\nsig = \"a\"\n";
        let err = Config::from_toml_str(toml).unwrap_err();
        assert_invalid_contains(&err, "malformed");
    }

    #[test]
    fn rule_for_unknown_server_is_invalid() {
        let toml = "[servers.a]\ncommand = \"x\"\n[[policy.allow]]\nsig = \"b__*\"\n";
        let err = Config::from_toml_str(toml).unwrap_err();
        assert_invalid_contains(&err, "unknown server 'b'");
    }

    #[test]
    fn args_on_wildcard_tool_is_invalid() {
        let toml = "[servers.a]\ncommand = \"x\"\n[[policy.allow]]\nsig = \"a__*\"\nargs = { k = \"v\" }\n";
        let err = Config::from_toml_str(toml).unwrap_err();
        assert_invalid_contains(&err, "require a concrete tool");
    }

    #[test]
    fn validation_collects_all_problems_at_once() {
        let toml = "[servers.a__b]\ncommand = \"\"\n[[policy.allow]]\nsig = \"nope\"\n";
        let err = Config::from_toml_str(toml).unwrap_err();
        match err {
            ConfigError::Invalid(problems) => assert!(
                problems.len() >= 3,
                "expected all problems reported, got: {problems:?}"
            ),
            other => panic!("expected Invalid, got: {other}"),
        }
    }

    #[test]
    fn parse_sig_splits_on_first_separator() {
        let sig = parse_sig("zastava__alpha__ping").expect("valid sig");
        assert_eq!(sig.server, "zastava");
        assert_eq!(sig.tool, "alpha__ping");
        assert_eq!(parse_sig("a__*").unwrap().tool, "*");
        assert!(parse_sig("a").is_none());
        assert!(parse_sig("__x").is_none());
        assert!(parse_sig("a__").is_none());
        assert!(parse_sig("a__pre*").is_none(), "частичные wildcard — не v0");
        assert!(parse_sig("*__x").is_none());
    }

    fn assert_invalid_contains(err: &ConfigError, needle: &str) {
        match err {
            ConfigError::Invalid(problems) => assert!(
                problems.iter().any(|p| p.contains(needle)),
                "no problem containing '{needle}' in: {problems:?}"
            ),
            other => panic!("expected Invalid, got: {other}"),
        }
    }
}

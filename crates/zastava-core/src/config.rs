//! Модель `zastava.toml`.
//!
//! Правило несёт текстовую сигнатуру `<server>__<tool>` / `<server>__*` и
//! опциональную таблицу `args` с матчерами на значения аргументов (M3).
//! Разделитель неймспейса — `__`, поэтому имена серверов не могут его
//! содержать (иначе сигнатуры становятся неоднозначными).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ConfigError;
use crate::pathish;

/// Разделитель неймспейса между сервером и инструментом.
pub const NS_SEP: &str = "__";

/// Корень конфига (`zastava.toml`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
    /// Правила канонизации аргументов для журнала.
    #[serde(default)]
    pub canon: CanonConfig,
}

/// Секция `[canon]` — что из аргументов попадает в журнал открыто.
///
/// Дефолт (whitelist ключей-идентификаторов) живёт в модуле `canon`; здесь
/// только пользовательские поправки к нему.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonConfig {
    /// Дополнительные ключи сверх дефолтного whitelist.
    #[serde(default)]
    pub extra_keys: Vec<String>,
    /// Ключи, которые не писать никогда, даже если они в whitelist.
    #[serde(default)]
    pub deny_keys: Vec<String>,
    /// Точечные правила на инструмент: `[[canon.rules]]`.
    #[serde(default)]
    pub rules: Vec<CanonRuleConfig>,
}

/// Одно правило канонизации для конкретного инструмента.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonRuleConfig {
    /// Сигнатура инструмента: `<server>__<tool>` (без `*`).
    pub sig: String,
    /// Ключи аргументов, попадающие в сигнатуру. Заменяют общий whitelist
    /// целиком, а не дополняют его: точечное правило — это заявление
    /// «для этого инструмента ресурс определяют ровно эти ключи».
    pub keys: Vec<String>,
}

/// Секция `[proxy]`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Таймаут одного downstream-вызова, мс. Зависший downstream не должен
    /// вешать весь гейтвей (контракт падения, решение 2A).
    #[serde(default = "default_call_timeout_ms")]
    pub call_timeout_ms: u64,
    /// Таймаут initialize-хендшейка с downstream при старте, мс.
    #[serde(default = "default_initialize_timeout_ms")]
    pub initialize_timeout_ms: u64,
    /// Таймаут выдачи списка инструментов, мс. Отдельный и КОРОТКИЙ:
    /// клиент ждёт tools/list синхронно, и бюджет вызова (десятки секунд)
    /// здесь означал бы, что пара молчащих downstream'ов гарантированно
    /// пересиживает таймаут клиента (находка верификации M1).
    #[serde(default = "default_list_timeout_ms")]
    pub list_timeout_ms: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            call_timeout_ms: default_call_timeout_ms(),
            initialize_timeout_ms: default_initialize_timeout_ms(),
            list_timeout_ms: default_list_timeout_ms(),
        }
    }
}

fn default_call_timeout_ms() -> u64 {
    60_000
}

fn default_initialize_timeout_ms() -> u64 {
    15_000
}

fn default_list_timeout_ms() -> u64 {
    10_000
}

/// Один downstream-сервер (stdio; url-транспорт — вне v0.1).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Исполняемый файл (на Windows npx-серверы запускаются через `cmd /c` —
    /// этим занимается proxy-слой, в конфиге пишется как в клиентах).
    pub command: String,
    /// Аргументы команды.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Переменные окружения процесса.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Рабочая директория процесса.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Режим применения политик.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    /// Deny-by-default — security-питч проекта.
    #[default]
    Deny,
    /// Разрешать непокрытое (осознанный опт-аут).
    Allow,
}

/// Секция `[policy]`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Сигнатура: `<server>__<tool>` или `<server>__*`.
    pub sig: String,
    /// Аргументные матчеры: ключ аргумента → условие на его значение.
    ///
    /// Матчеры применяются к СЫРЫМ аргументам вызова, а не к канонизованному
    /// поднабору из журнала: префикс пути должен значить именно путь, а не
    /// его усечённую для лога версию. Мост между журналом и правилами —
    /// `zastava learn`, который переводит наблюдения в матчеры.
    #[serde(default)]
    pub args: Option<BTreeMap<String, ArgMatcher>>,
    /// Требовать, чтобы в вызове не было аргументов сверх перечисленных.
    ///
    /// По умолчанию правило ограничивает только названные ключи, а прочие
    /// свободны — этого хватает, когда ресурс определяет один ключ (`repo`).
    /// Там, где на ресурс может указывать несколько разных ключей
    /// (`path` и `paths`), опция закрывает обход через непокрытый ключ.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deny_extra_args: bool,
}

/// Условие на значение одного аргумента.
///
/// В TOML пишется либо строкой (точное совпадение), либо таблицей:
/// ```toml
/// args = { repo = "gorka2354/zastava" }              # точное
/// args = { path = { prefix = "C:/work/zastava" } }   # префикс
/// args = { repo = { any_of = ["a/b", "c/d"] } }      # список
/// ```
/// Регулярных выражений здесь нет намеренно: политика безопасности должна
/// читаться однозначно с первого взгляда, а regex приносит и ReDoS, и споры
/// о том, что именно матчится.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ArgMatcher {
    /// Точное совпадение строки.
    Exact(String),
    /// Совпадение по префиксу.
    Prefix(PrefixMatcher),
    /// Совпадение с любым значением из списка.
    AnyOf(AnyOfMatcher),
}

/// Совпадает ли значение с префиксным правилом.
///
/// Сравниваются НЕ строки, а компоненты пути. Строковый `starts_with`
/// пропускал два обхода, воспроизведённых на живом гейтвее (ревью M3):
/// - `C:/work/zastava/../../Users/alice/.ssh` — `..` уводит наружу;
/// - `C:/work/zastava-private` — соседний каталог, чьё имя просто начинается
///   так же.
///
/// Поэтому: обе стороны раскладываются лексически ([`pathish::resolve`]),
/// `..` схлопывается, выход за корень отвергается целиком, а совпадение
/// обязано заканчиваться НА ГРАНИЦЕ компонента.
///
/// Регистр и `\` против `/` складываются: на Windows `C:\Work` и `c:/work` —
/// одно место, и правило, чувствительное к регистру, обходилось бы его
/// сменой. Приведение одинаково на всех платформах — политика обязана
/// значить одно и то же на любой машине.
///
/// Точные матчеры (`exact`, `any_of`) остаются побайтовыми.
fn prefix_matches(prefix: &str, actual: &str) -> bool {
    let (Some(want), Some(got)) = (pathish::resolve(prefix), pathish::resolve(actual)) else {
        // Значение или префикс вышли за собственный корень — не совпадение.
        return false;
    };
    let want = want.render().to_lowercase();
    let got = got.render().to_lowercase();

    if got == want {
        return true;
    }
    let Some(tail) = got.strip_prefix(&want) else {
        return false;
    };
    // Граница: либо префикс сам ею кончается, либо остаток с неё начинается.
    // Без этой проверки `zastava` покрывал бы `zastava-private`.
    want.ends_with(pathish::is_boundary) || tail.starts_with(pathish::is_boundary)
}

/// `{ prefix = "..." }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixMatcher {
    /// Требуемый префикс значения.
    pub prefix: String,
}

/// `{ any_of = [...] }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnyOfMatcher {
    /// Допустимые значения.
    pub any_of: Vec<String>,
}

impl ArgMatcher {
    /// Совпадает ли матчер с сырым значением аргумента.
    ///
    /// Не-строки не совпадают ни с чем: политика рассуждает о строковых
    /// идентификаторах, и «число 5 похоже на строку "5"» — ровно тот сорт
    /// догадки, из-за которого гейт можно обойти.
    pub fn matches(&self, value: &Value) -> bool {
        let Value::String(actual) = value else {
            return false;
        };
        match self {
            ArgMatcher::Exact(expected) => actual == expected,
            ArgMatcher::Prefix(m) => prefix_matches(&m.prefix, actual),
            ArgMatcher::AnyOf(m) => m.any_of.iter().any(|candidate| candidate == actual),
        }
    }

    /// Проблемы матчера для доменной валидации (пустые значения и т.п.).
    fn problems(&self) -> Vec<&'static str> {
        let mut problems = Vec::new();
        match self {
            ArgMatcher::Exact(value) => {
                if value.is_empty() {
                    problems.push("empty exact value");
                }
            }
            ArgMatcher::Prefix(m) => {
                if m.prefix.is_empty() {
                    // Пустой префикс совпадает с чем угодно: это не сужение,
                    // а бесшумное «разрешить всё» с видом ограничения.
                    problems.push("empty prefix matches any value");
                }
            }
            ArgMatcher::AnyOf(m) => {
                if m.any_of.is_empty() {
                    problems.push("empty any_of matches nothing");
                }
                if m.any_of.iter().any(String::is_empty) {
                    problems.push("empty value in any_of");
                }
            }
        }
        problems
    }
}

/// Секция `[log]`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
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
            // Хвостовой '_' делает неймспейс неоднозначным: сервер `alpha_`
            // с инструментом `ping` и сервер `alpha` с инструментом `_ping`
            // дают одно внешнее имя `alpha___ping`, а разбор по ПЕРВОМУ `__`
            // всегда выбирает короткий вариант — первый сервер стал бы
            // недоступен целиком (находка верификации M1).
            if name.ends_with('_') {
                problems.push(format!(
                    "server name '{name}' must not end with '_': it makes '{NS_SEP}' ambiguous"
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
                        for (key, matcher) in args {
                            if key.is_empty() {
                                problems.push(format!("rule '{}': empty args key", rule.sig));
                            }
                            for problem in matcher.problems() {
                                problems.push(format!(
                                    "rule '{}': args['{key}']: {problem}",
                                    rule.sig
                                ));
                            }
                        }
                    }
                    // `deny_extra_args` без матчеров означает «вызов вообще без
                    // аргументов» — почти всегда это забытая таблица args, а не
                    // намерение, и молча запрещать все вызовы инструмента мы
                    // не станем.
                    if rule.deny_extra_args
                        && rule.args.as_ref().is_none_or(BTreeMap::is_empty)
                    {
                        problems.push(format!(
                            "rule '{}': deny_extra_args requires an args table",
                            rule.sig
                        ));
                    }
                }
                None => problems.push(format!(
                    "rule '{}' is malformed: expected '<server>{NS_SEP}<tool>' or '<server>{NS_SEP}*'",
                    rule.sig
                )),
            }
        }

        for rule in &self.canon.rules {
            match parse_sig(&rule.sig) {
                Some(sig) => {
                    if sig.tool == "*" {
                        problems.push(format!(
                            "canon rule '{}': a concrete tool is required, not '*'",
                            rule.sig
                        ));
                    }
                    if !self.servers.contains_key(sig.server) {
                        problems.push(format!(
                            "canon rule '{}' references unknown server '{}'",
                            rule.sig, sig.server
                        ));
                    }
                }
                None => problems.push(format!(
                    "canon rule '{}' is malformed: expected '<server>{NS_SEP}<tool>'",
                    rule.sig
                )),
            }
            if rule.keys.iter().any(String::is_empty) {
                problems.push(format!("canon rule '{}': empty key", rule.sig));
            }
        }

        if self.proxy.call_timeout_ms == 0 {
            problems.push("proxy.call_timeout_ms must be > 0".to_string());
        }
        if self.proxy.initialize_timeout_ms == 0 {
            problems.push("proxy.initialize_timeout_ms must be > 0".to_string());
        }
        if self.proxy.list_timeout_ms == 0 {
            problems.push("proxy.list_timeout_ms must be > 0".to_string());
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems))
        }
    }
}

/// Символы, допустимые в именах, которые мы САМИ куда-то записываем.
/// Whitelist, а не blacklist: сигнатура попадает в TOML-конфиг
/// (`zastava allow`), в copy-paste сниппеты (`zastava learn`) и в вывод
/// команд, поэтому кавычки, переводы строк и управляющие символы должны быть
/// невозможны в принципе, а не отфильтрованы на месте использования.
pub fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// Безопасна ли сигнатура для записи в конфиг или в готовый к вставке
/// сниппет. Проверка отделена от `parse_sig` намеренно: разбор существующего
/// конфига должен быть терпимым (иначе правило на инструмент с непривычным
/// символом не даёт гейтвею стартовать вообще), а вот ГЕНЕРАЦИЯ текста
/// обязана быть строгой — именно там жила инъекция (ревью M1).
pub fn is_safe_sig(sig: &str) -> bool {
    match parse_sig(sig) {
        Some(parsed) => {
            parsed.server.chars().all(is_name_char)
                && (parsed.tool == "*" || parsed.tool.chars().all(is_name_char))
        }
        None => false,
    }
}

/// Экранирует недоверенное имя для БЕЗОПАСНОГО показа и записи в журнал:
/// всё вне whitelist уходит в `\xNN`/`\u{NNNN}`. Возвращает пару
/// (экранированное имя, менялось ли оно) — факт подмены обязан быть виден.
pub fn sanitize_name(name: &str) -> (String, bool) {
    let mut out = String::with_capacity(name.len());
    let mut changed = false;
    for c in name.chars() {
        if is_name_char(c) {
            out.push(c);
        } else {
            changed = true;
            let code = c as u32;
            if code < 0x100 {
                out.push_str(&format!("\\x{code:02x}"));
            } else {
                out.push_str(&format!("\\u{{{code:x}}}"));
            }
        }
    }
    (out, changed)
}

/// Разбирает текстовую сигнатуру правила. Сплит по ПЕРВОМУ `__`: имя
/// инструмента справа может содержать `__` (инструменты downstream'ов этого
/// не запрещают), имя сервера — нет (валидируется отдельно).
///
/// Структурная проверка, БЕЗ ограничения набора символов: конфиг,
/// написанный руками под инструмент с экзотическим именем, обязан грузиться.
/// Для путей, где мы сами что-то генерируем, есть `is_safe_sig`.
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
        assert_eq!(
            rule.args.as_ref().unwrap()["repo"],
            ArgMatcher::Exact("gorka2354/zastava".into())
        );
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
    fn server_name_with_trailing_underscore_is_invalid() {
        let err = Config::from_toml_str("[servers.alpha_]\ncommand = \"x\"\n").unwrap_err();
        assert_invalid_contains(&err, "must not end with");
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

    #[test]
    fn is_safe_sig_rejects_everything_we_would_have_to_quote() {
        assert!(is_safe_sig("a__ping"));
        assert!(is_safe_sig("a__*"));
        assert!(is_safe_sig("a__tool.with-dots_and_2"));
        // Инъекция TOML/JSON через сигнатуру: кавычки, переводы строк,
        // комментарии и пробелы не должны считаться безопасными.
        let injection = concat!(
            "a__ping\"",
            "
[[policy.allow]]
sig = ",
            "\"a__evil"
        );
        assert!(!is_safe_sig(injection));
        assert!(!is_safe_sig("a__ping evil"));
        assert!(!is_safe_sig("a__ping#"));
        assert!(
            !is_safe_sig("a__пинг"),
            "не-ASCII в генерируемый текст не пускаем"
        );
        assert!(!is_safe_sig("a"), "без разделителя — не сигнатура");
    }

    #[test]
    fn parse_sig_stays_lenient_so_hand_written_configs_load() {
        // Строгий charset в разборе означал бы, что конфиг с правилом на
        // инструмент с непривычным символом не даёт гейтвею стартовать.
        let parsed = parse_sig("a__странный:инструмент").expect("разбор терпим");
        assert_eq!(parsed.server, "a");
        assert!(
            !is_safe_sig("a__странный:инструмент"),
            "но записывать такое нельзя"
        );
    }

    #[test]
    fn sanitize_name_escapes_and_reports_change() {
        let hostile = concat!("ping", "\n", "evil");
        let (safe, changed) = sanitize_name(hostile);
        assert!(changed);
        assert!(!safe.contains('\n'), "{safe}");
        assert!(safe.contains("\\x0a"), "перевод строки экранирован: {safe}");
        let (untouched, changed) = sanitize_name("plain_tool-1.2");
        assert!(!changed);
        assert_eq!(untouched, "plain_tool-1.2");
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

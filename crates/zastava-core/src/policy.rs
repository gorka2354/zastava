//! PolicyEngine: единый движок с M1 (решение ревью 5A).
//!
//! v2 (M3) — то, ради чего проект существует: правила различают вызовы по
//! АРГУМЕНТАМ. Клиентский `permissions.allow` умеет только «инструмент можно
//! или нельзя»; «github можно, но только в этот репозиторий» он выразить не
//! может, и именно этот зазор закрывает застава.
//!
//! Матчинг идёт по сырым аргументам вызова (см. `ArgMatcher`), первое
//! подошедшее правило выигрывает.
//!
//! Дефолтный режим — warn (пост-спайк): tool-level гейтинг делегирован
//! клиентскому `permissions.allow`, enforce включается осознанно.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::config::{parse_sig, ArgMatcher, DefaultAction, PolicyConfig, PolicyMode};

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
    /// Матчеры на аргументы. Пусто = правило tool-level.
    args: BTreeMap<String, ArgMatcher>,
    /// Запрещать аргументы сверх перечисленных в `args`.
    deny_extra_args: bool,
    /// Исходная сигнатура для журнала и сообщений.
    raw: String,
}

impl CompiledRule {
    /// Покрывает ли правило пару (server, tool) без учёта аргументов.
    fn covers(&self, server: &str, tool: &str) -> bool {
        self.server == server && (self.tool == "*" || self.tool == tool)
    }

    /// Подходит ли правило под конкретный вызов.
    fn matches(&self, server: &str, tool: &str, args: &Map<String, Value>) -> bool {
        if self.server != server || (self.tool != "*" && self.tool != tool) {
            return false;
        }
        // Отсутствующий аргумент — не совпадение: правило «только этот repo»
        // обязано отклонять вызов вообще без repo, иначе сужение обходится
        // простым опусканием ключа.
        let all_matched = self
            .args
            .iter()
            .all(|(key, matcher)| args.get(key).is_some_and(|value| matcher.matches(value)));
        if !all_matched {
            return false;
        }
        if self.deny_extra_args && args.keys().any(|key| !self.args.contains_key(key)) {
            return false;
        }
        true
    }
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
                    args: rule.args.clone().unwrap_or_default(),
                    deny_extra_args: rule.deny_extra_args,
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

    /// Действие для непокрытых вызовов.
    pub fn default_action(&self) -> DefaultAction {
        self.default
    }

    /// Сколько правил скомпилировано.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Правило, покрывающее пару (server, tool), и ДЕЙСТВУЕТ ли его сужение.
    ///
    /// Второй элемент — не «у правила есть матчеры», а «доступ действительно
    /// сужен». Разница существенна: выигрывает первое подошедшее правило, но
    /// вызов, не совпавший с матчерами, идёт дальше по списку — и широкое
    /// правило НИЖЕ пропускает всё, что узкое отклонило. Пока здесь стояло
    /// «есть матчеры», `learn` печатал «уже сужено» ровно в тот момент, когда
    /// гейт открыт настежь (находка ревью M3, независимо у двух линз).
    pub fn covering_rule(&self, server: &str, tool: &str) -> Option<(&str, bool)> {
        let index = self
            .rules
            .iter()
            .position(|rule| rule.covers(server, tool))?;
        let rule = &self.rules[index];
        if rule.args.is_empty() {
            return Some((rule.raw.as_str(), false));
        }
        // Сужение действует, только если ниже нет правила без матчеров на ту
        // же пару — иначе оно снято, и честный ответ «покрыто тем правилом».
        match self.broad_rule_after(index, server, tool) {
            Some(defeating) => Some((defeating.raw.as_str(), false)),
            None => Some((rule.raw.as_str(), true)),
        }
    }

    /// Первое правило ПОСЛЕ `index`, покрывающее пару без аргументных
    /// ограничений.
    fn broad_rule_after(&self, index: usize, server: &str, tool: &str) -> Option<&CompiledRule> {
        self.rules[index + 1..]
            .iter()
            .find(|rule| rule.args.is_empty() && rule.covers(server, tool))
    }

    /// Аргументные правила, чьё сужение снято более поздним широким
    /// правилом: `(суженное правило, правило, которое его снимает)`.
    ///
    /// Ровно это делает `zastava allow <server>__*`, дописывающий правило в
    /// конец файла: аргументные ограничения перестают действовать, а на вид
    /// остаются в конфиге.
    pub fn defeated_narrowings(&self) -> Vec<(&str, &str)> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| !rule.args.is_empty())
            .filter_map(|(index, rule)| {
                let tool = if rule.tool == "*" { "*" } else { &rule.tool };
                self.broad_rule_after(index, &rule.server, tool)
                    .map(|defeating| (rule.raw.as_str(), defeating.raw.as_str()))
            })
            .collect()
    }

    /// Сигнатуры правил, чьё аргументное сужение ДЕЙСТВУЕТ. Снимок для
    /// сравнения политики до и после reload.
    pub fn effective_narrowings(&self) -> BTreeSet<String> {
        let defeated: BTreeSet<&str> = self
            .defeated_narrowings()
            .into_iter()
            .map(|(narrow, _)| narrow)
            .collect();
        self.rules
            .iter()
            .filter(|rule| !rule.args.is_empty() && !defeated.contains(rule.raw.as_str()))
            .map(|rule| rule.raw.clone())
            .collect()
    }

    /// Решение по вызову инструмента `server`/`tool` с аргументами `args`.
    pub fn decide(&self, server: &str, tool: &str, args: &Map<String, Value>) -> Decision {
        let matched = self
            .rules
            .iter()
            .find(|rule| rule.matches(server, tool, args));

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
    fn prefix_matcher_narrows_by_path() {
        let toml = r#"
[servers.fs]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "fs__read_file"
args = { path = { prefix = "C:/work/zastava" } }
"#;
        let e = engine(toml);
        let inside = e.decide(
            "fs",
            "read_file",
            &args(&[("path", "C:/work/zastava/src/main.rs")]),
        );
        assert_eq!(inside.verdict, Verdict::Allow);

        let outside = e.decide(
            "fs",
            "read_file",
            &args(&[("path", "C:/Users/alice/.ssh/id")]),
        );
        assert!(outside.blocks(), "путь вне префикса должен блокироваться");
    }

    #[test]
    fn prefix_is_a_directory_boundary_not_a_string_prefix() {
        // Три независимых ревью M3 воспроизвели на живом гейтвее один и тот же
        // обход: `prefix` был `starts_with` по строке. Правило продаётся как
        // «только в этом проекте» — значит, обязано быть границей каталога.
        let toml = r#"
[servers.fs]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "fs__write"
args = { path = { prefix = "C:/work/zastava" } }
"#;
        let e = engine(toml);
        let verdict = |path: &str| e.decide("fs", "write", &args(&[("path", path)]));

        // Внутри границы — проходит, в том числе с windows-разделителями.
        assert!(!verdict(r"C:\work\zastava\src\main.rs").blocks());
        assert!(!verdict("C:/work/zastava").blocks(), "сама граница");
        assert!(
            !verdict(r"c:\WORK\Zastava\x").blocks(),
            "регистр складывается"
        );

        // `..` уводит наружу.
        assert!(
            verdict(r"C:\work\zastava\..\..\Users\alice\.ssh\authorized_keys").blocks(),
            "обход через .. обязан блокироваться"
        );
        assert!(verdict("C:/work/zastava/../.env").blocks());
        // Возврат внутрь границы — законный путь, блокировать его не за что.
        assert!(!verdict("C:/work/zastava/src/../notes.md").blocks());

        // Сосед, чьё имя просто начинается так же.
        assert!(
            verdict("C:/work/zastava-private/secrets.env").blocks(),
            "граница компонента обязана проверяться"
        );
        assert!(verdict("C:/work/zastava.bak/id_rsa").blocks());
        assert!(verdict("C:/work/zastavaEVIL/x").blocks());
    }

    #[test]
    fn hash_and_question_are_not_path_boundaries() {
        // P1 верификации M3: `?` и `#` считались границей компонента и для
        // файловых путей, поэтому каталог `zastava#private` проходил под
        // правилом на `zastava`. Через junction на системный каталог это
        // давало доступ ко всему диску без прав администратора.
        let toml = r#"
[servers.fs]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "fs__write"
args = { path = { prefix = "C:/work/zastava" } }
"#;
        let e = engine(toml);
        let verdict = |path: &str| e.decide("fs", "write", &args(&[("path", path)]));
        assert!(verdict("C:/work/zastava#private/secrets.env").blocks());
        assert!(verdict("C:/work/zastava?evil/x").blocks());
        assert!(verdict("C:/work/zastava#esc/hosts").blocks());
        // Внутри границы `#` в имени файла по-прежнему допустим.
        assert!(!verdict("C:/work/zastava/issue#42.md").blocks());
    }

    #[test]
    fn case_is_folded_only_where_the_namespace_itself_ignores_it() {
        // На Windows `C:\Work` и `c:/work` — одно место, и правило, чувствительное
        // к регистру, обходилось бы его сменой. На POSIX `/home/alice/PROJ` — ДРУГОЙ
        // каталог, и складывать там регистр значит расширять правило за пределы
        // написанного (находка верификации M3). Решает вид значения, а не текущая
        // ОС: политика обязана значить одно и то же на любой машине.
        let win = engine(
            "[servers.fs]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"fs__w\"\nargs = { path = { prefix = \"C:/work/zastava\" } }\n",
        );
        assert!(!win
            .decide("fs", "w", &args(&[("path", r"c:\WORK\Zastava\x")]))
            .blocks());

        let posix = engine(
            "[servers.fs]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"fs__w\"\nargs = { path = { prefix = \"/home/alice/proj\" } }\n",
        );
        assert!(!posix
            .decide("fs", "w", &args(&[("path", "/home/alice/proj/src/x")]))
            .blocks());
        assert!(
            posix
                .decide("fs", "w", &args(&[("path", "/home/alice/PROJ/secret")]))
                .blocks(),
            "на POSIX это другой каталог"
        );
    }

    #[test]
    fn backslash_in_url_authority_is_refused_rather_than_guessed() {
        // `https://api.example.com\@evil.tld/x`: наш разбор давал хост
        // api.example.com, а Python/Go/Java — evil.tld. Гейт разрешал бы вызов
        // к одному хосту, downstream шёл бы к другому (обход allow-листа).
        let e = engine(
            "[servers.http]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"http__get\"\nargs = { url = { prefix = \"https://api.example.com\" } }\n",
        );
        assert!(e
            .decide(
                "http",
                "get",
                &args(&[("url", r"https://api.example.com\@evil.tld/x")])
            )
            .blocks());
    }

    #[test]
    fn a_prefix_that_collapses_to_nothing_matches_nothing() {
        // `.` и `a/..` схлопываются в пустоту и совпали бы с любым путём.
        for bad in [".", "./", "a/.."] {
            let toml = format!(
                "[servers.fs]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"fs__w\"\nargs = {{ path = {{ prefix = \"{bad}\" }} }}\n"
            );
            // Такой конфиг обязан отвергаться на входе...
            let err = Config::from_toml_str(&toml).unwrap_err();
            assert!(
                format!("{err}").contains("collapses to nothing"),
                "{bad}: {err}"
            );
            // ...а сам матчер — не совпадать, даже если конфиг обошёл проверку.
            let matcher = ArgMatcher::Prefix(crate::config::PrefixMatcher {
                prefix: bad.to_string(),
            });
            assert!(!matcher.matches(&serde_json::json!("/etc/shadow")), "{bad}");
        }
    }

    #[test]
    fn flat_identifiers_keep_plain_string_prefix_semantics() {
        // Граница компонента осмысленна для путей, но не для плоских
        // идентификаторов: `prefix = "prod-"` обязан покрывать `prod-a`,
        // иначе enforce тихо отказывает законным вызовам (находка
        // верификации M3 — регрессия, внесённая фиксом границы).
        let e = engine(
            "[servers.k8s]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"k8s__get\"\nargs = { namespace = { prefix = \"prod-\" } }\n",
        );
        assert!(!e
            .decide("k8s", "get", &args(&[("namespace", "prod-a")]))
            .blocks());
        assert!(e
            .decide("k8s", "get", &args(&[("namespace", "staging-a")]))
            .blocks());

        // А иерархический идентификатор границу сохраняет.
        let repo = engine(
            "[servers.gh]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"gh__get\"\nargs = { repo = { prefix = \"gorka2354/\" } }\n",
        );
        assert!(!repo
            .decide("gh", "get", &args(&[("repo", "gorka2354/zastava")]))
            .blocks());
    }

    #[test]
    fn encoded_traversal_and_drive_relative_paths_never_match() {
        let e = engine(
            "[servers.fs]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n[[policy.allow]]\nsig = \"fs__w\"\nargs = { path = { prefix = \"C:/work/zastava\" } }\n",
        );
        let verdict = |path: &str| e.decide("fs", "w", &args(&[("path", path)]));
        // Мы не декодируем, но downstream может — гейт не должен разрешать
        // то, чего сам не проверил.
        assert!(verdict("C:/work/zastava/%2e%2e/%2e%2e/Windows/x").blocks());
        assert!(verdict("C:/work/zastava/..%2fWindows").blocks());
        // `C:work` — относительно текущего каталога диска, который нам неизвестен.
        assert!(verdict("C:work/zastava/x").blocks());
    }

    #[test]
    fn url_prefix_covers_paths_and_queries_but_not_other_hosts() {
        let toml = r#"
[servers.http]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "http__fetch"
args = { url = { prefix = "https://api.example.com" } }
"#;
        let e = engine(toml);
        let verdict = |url: &str| e.decide("http", "fetch", &args(&[("url", url)]));
        assert!(!verdict("https://api.example.com/v1/users?page=2").blocks());
        assert!(!verdict("https://api.example.com").blocks());
        assert!(!verdict("https://api.example.com?x=1").blocks());
        assert!(
            verdict("https://api.example.com.evil.tld/x").blocks(),
            "чужой хост с тем же началом имени"
        );
        assert!(verdict("https://other.example.com/v1").blocks());
    }

    #[test]
    fn any_of_matcher_accepts_listed_values_only() {
        let toml = r#"
[servers.github]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "github__create_issue"
args = { repo = { any_of = ["me/a", "me/b"] } }
"#;
        let e = engine(toml);
        assert_eq!(
            e.decide("github", "create_issue", &args(&[("repo", "me/b")]))
                .verdict,
            Verdict::Allow
        );
        assert!(e
            .decide("github", "create_issue", &args(&[("repo", "them/c")]))
            .blocks());
    }

    #[test]
    fn unlisted_args_are_free_unless_deny_extra_args_is_set() {
        let lax = r#"
[servers.fs]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "fs__read"
args = { path = "/safe" }
"#;
        let with_extra = args(&[("path", "/safe"), ("encoding", "utf-8")]);
        assert_eq!(
            engine(lax).decide("fs", "read", &with_extra).verdict,
            Verdict::Allow,
            "по умолчанию неперечисленные ключи не ограничены"
        );

        let strict = lax.replace(
            "args = { path = \"/safe\" }",
            "args = { path = \"/safe\" }\ndeny_extra_args = true",
        );
        assert!(
            engine(&strict).decide("fs", "read", &with_extra).blocks(),
            "deny_extra_args закрывает обход через непокрытый ключ"
        );
        assert_eq!(
            engine(&strict)
                .decide("fs", "read", &args(&[("path", "/safe")]))
                .verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn narrow_rule_before_broad_one_actually_narrows() {
        // Порядок правил — это семантика: сузить доступ можно только
        // правилом, стоящим ВЫШЕ широкого.
        let toml = r#"
[servers.github]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "github__create_issue"
args = { repo = "me/mine" }
[[policy.allow]]
sig = "github__read_issue"
"#;
        let e = engine(toml);
        assert!(e
            .decide("github", "create_issue", &args(&[("repo", "victim/repo")]))
            .blocks());
        assert_eq!(
            e.decide("github", "read_issue", &Map::new()).verdict,
            Verdict::Allow
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
    fn a_broad_rule_below_defeats_the_narrow_one_and_we_say_so() {
        // Ровно то, что делает `zastava allow <server>__*`: правило
        // дописывается в конец и снимает все аргументные ограничения, оставаясь
        // на вид безобидной строкой в конфиге (P1 ревью M3).
        let toml = r#"
[servers.fs]
command = "x"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "fs__read"
args = { path = { prefix = "C:/work/zastava" } }
[[policy.allow]]
sig = "fs__*"
"#;
        let e = engine(toml);
        // Фактически сужения больше нет.
        assert!(!e
            .decide("fs", "read", &args(&[("path", "C:/Users/alice/.ssh/id")]))
            .blocks());
        // И движок обязан это признавать, а не показывать правило живым.
        assert_eq!(e.defeated_narrowings(), vec![("fs__read", "fs__*")]);
        assert!(
            e.effective_narrowings().is_empty(),
            "снятое сужение не должно считаться действующим"
        );
        assert_eq!(
            e.covering_rule("fs", "read"),
            Some(("fs__*", false)),
            "learn обязан узнать, что сужение снято"
        );
    }

    #[test]
    fn a_narrow_rule_without_a_broad_one_below_stays_effective() {
        let toml = r#"
[servers.fs]
command = "x"
[[policy.allow]]
sig = "fs__read"
args = { path = { prefix = "C:/work/zastava" } }
[[policy.allow]]
sig = "fs__list"
"#;
        let e = engine(toml);
        assert!(e.defeated_narrowings().is_empty());
        assert_eq!(
            e.effective_narrowings().into_iter().collect::<Vec<_>>(),
            vec!["fs__read".to_string()]
        );
        assert_eq!(e.covering_rule("fs", "read"), Some(("fs__read", true)));
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

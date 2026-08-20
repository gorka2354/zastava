//! `zastava learn`: черновики правил из наблюдений.
//!
//! Человек, жмущий «allow не глядя», не станет писать YAML не глядя — правила
//! должны рождаться из журнала. M1 предлагал только tool-level правила; M3
//! добавляет главное — АРГУМЕНТНЫЕ, собранные из `canonical_subset`.
//!
//! Мост между журналом и политикой проходит здесь. В журнале лежат
//! канонизованные значения (усечённый путь `C:/work/proj/…`, URL до хоста), а
//! матчеры работают по сырым аргументам вызова — значит, наблюдение надо
//! перевести: усечённый путь становится префиксом, целое значение — точным
//! совпадением, несколько значений — списком.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{
    is_safe_sig, sanitize_name, AnyOfMatcher, ArgMatcher, Config, PrefixMatcher, RuleConfig, NS_SEP,
};
use crate::policy::PolicyEngine;
use crate::record::CallRecord;

/// Сколько разных значений ключа ещё считаем «набором», а не разнообразием.
/// Выше порога ключ не идентифицирует ресурс: правило из двадцати значений
/// никто не прочитает, а сузит оно ровно ничего.
const MAX_DISTINCT_VALUES: usize = 4;

/// Маркер усечения пути, который ставит канонизация.
const TRUNCATION_MARK: &str = "/…";

/// Черновик одного правила.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Сигнатура `<server>__<tool>`.
    pub sig: String,
    /// Предлагаемые матчеры (None — правило tool-level).
    pub args: Option<BTreeMap<String, ArgMatcher>>,
    /// Сколько вызовов наблюдалось — на этом человек и строит доверие.
    pub calls: usize,
}

impl Proposal {
    /// Сужает ли черновик доступ по аргументам.
    pub fn is_narrowed(&self) -> bool {
        self.args.is_some()
    }
}

/// Результат генерации черновиков.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LearnOutput {
    /// Черновики правил для непокрытых сигнатур.
    pub proposals: Vec<Proposal>,
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
    /// Сигнатуры с символами вне whitelist — в сниппеты НЕ попадают.
    /// Имя инструмента выбирает downstream, а сниппет пользователь копирует
    /// в конфиг: без этого фильтра враждебный сервер дописывал туда свои
    /// правила и даже свои `[servers.*]` (P1 верификации фиксов M1).
    /// Показываются экранированными, чтобы факт попытки был виден.
    pub suspicious: Vec<String>,
}

impl LearnOutput {
    /// Сигнатуры предложенных правил.
    pub fn sigs(&self) -> Vec<&str> {
        self.proposals.iter().map(|p| p.sig.as_str()).collect()
    }
}

/// Наблюдения по одной сигнатуре.
#[derive(Default)]
struct Observations {
    calls: usize,
    /// Ключ → множество канонических значений.
    values: BTreeMap<String, BTreeSet<String>>,
    /// В скольких вызовах встречался ключ: требовать в правиле можно только
    /// то, что было в КАЖДОМ вызове, иначе правило отсечёт законные вызовы.
    key_hits: BTreeMap<String, usize>,
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
    let mut seen: BTreeMap<String, Observations> = BTreeMap::new();
    let mut narrowed: BTreeSet<String> = BTreeSet::new();
    let mut foreign: BTreeSet<String> = BTreeSet::new();
    let mut suspicious: BTreeSet<String> = BTreeSet::new();

    for record in records.iter().filter(|r| r.is_call()) {
        let sig = format!("{}{NS_SEP}{}", record.server, record.tool);
        // Имя инструмента приходит от downstream. Всё, что не проходит
        // whitelist, не попадает ни в один генерируемый текст.
        if !is_safe_sig(&sig) {
            let (escaped, _) = sanitize_name(&sig);
            suspicious.insert(escaped);
            continue;
        }
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
                let entry = seen.entry(sig).or_default();
                entry.calls += 1;
                for (key, value) in &record.canonical_subset {
                    entry
                        .values
                        .entry(key.clone())
                        .or_default()
                        .insert(value.clone());
                    *entry.key_hits.entry(key.clone()).or_default() += 1;
                }
            }
        }
    }

    let proposals: Vec<Proposal> = seen
        .into_iter()
        .map(|(sig, obs)| Proposal {
            args: matchers_for(&obs),
            sig,
            calls: obs.calls,
        })
        .collect();

    // Сниппеты собираются СЕРИАЛИЗАТОРАМИ, а не склейкой строк: даже после
    // whitelist-фильтра выше генерация текста из недоверенных имён обязана
    // идти через экранирование (тот же принцип, что в `import`).
    // Каждое правило сериализуется ОТДЕЛЬНЫМ документом и уже потом
    // склеивается. Иначе toml выносит все под-таблицы `args` в конец, и
    // матчер оказывается визуально оторван от своего правила — а инструкция
    // пользователю звучит «вычеркни лишнее»: удалив блок выше, он молча
    // переприкрепил бы сужение к чужому правилу.
    let toml_snippet = proposals
        .iter()
        .map(|p| {
            let doc = AllowDoc {
                policy: PolicyDoc {
                    allow: vec![RuleConfig {
                        sig: p.sig.clone(),
                        args: p.args.clone(),
                        deny_extra_args: false,
                    }],
                },
            };
            toml::to_string_pretty(&doc).unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(
            "
",
        );

    let client_allow_snippet = if proposals.is_empty() {
        String::new()
    } else {
        let allow: Vec<String> = proposals
            .iter()
            .map(|p| format!("mcp__zastava{NS_SEP}{}", p.sig))
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "permissions": { "allow": allow }
        }))
        .unwrap_or_default()
    };

    LearnOutput {
        proposals,
        toml_snippet,
        client_allow_snippet,
        narrowed: narrowed.into_iter().collect(),
        foreign: foreign.into_iter().collect(),
        suspicious: suspicious.into_iter().collect(),
    }
}

/// Переводит наблюдения по одной сигнатуре в матчеры.
///
/// `None` означает «сузить нечем» — предлагаем обычное tool-level правило.
/// Это нормальный исход: у половины инструментов аргументы вообще не
/// идентифицируют ресурс.
fn matchers_for(obs: &Observations) -> Option<BTreeMap<String, ArgMatcher>> {
    let mut matchers = BTreeMap::new();
    for (key, values) in &obs.values {
        // Ключ, встреченный не во всех вызовах, требовать нельзя: матчер
        // означает «аргумент обязан быть и обязан совпасть», и правило молча
        // отсекло бы законные вызовы без этого ключа.
        if obs.key_hits.get(key).copied().unwrap_or(0) != obs.calls {
            continue;
        }
        if values.len() > MAX_DISTINCT_VALUES {
            continue;
        }
        if values.iter().any(|v| !is_safe_value(v)) {
            continue;
        }
        if let Some(matcher) = matcher_for_values(values) {
            matchers.insert(key.clone(), matcher);
        }
    }
    (!matchers.is_empty()).then_some(matchers)
}

fn matcher_for_values(values: &BTreeSet<String>) -> Option<ArgMatcher> {
    // Усечённый путь в журнале описывает не значение, а границу: правилом он
    // становится префиксом. Смешивать усечённые и целые значения в один
    // any_of нельзя — получится список, который не совпадёт ни с чем.
    let truncated: Vec<&String> = values
        .iter()
        .filter(|v| v.ends_with(TRUNCATION_MARK))
        .collect();
    if !truncated.is_empty() {
        if truncated.len() != values.len() || values.len() != 1 {
            return None;
        }
        let stem = truncated[0].trim_end_matches(TRUNCATION_MARK);
        return (!stem.is_empty()).then(|| {
            ArgMatcher::Prefix(PrefixMatcher {
                prefix: stem.to_string(),
            })
        });
    }

    match values.len() {
        0 => None,
        1 => Some(ArgMatcher::Exact(
            values.iter().next().expect("len checked").clone(),
        )),
        _ => Some(ArgMatcher::AnyOf(AnyOfMatcher {
            any_of: values.iter().cloned().collect(),
        })),
    }
}

/// Значение из журнала попадает в текст, который пользователь вставит в
/// конфиг. Канонизация уже отсекла управляющие символы на записи, но журнал —
/// обычный файл, и доверять его содержимому на чтении мы не обязаны.
fn is_safe_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 200 && !value.chars().any(|c| c.is_control())
}

/// Обёртки для сериализации TOML-сниппета.
#[derive(serde::Serialize)]
struct AllowDoc {
    policy: PolicyDoc,
}

#[derive(serde::Serialize)]
struct PolicyDoc {
    allow: Vec<RuleConfig>,
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

    fn with_subset(server: &str, tool: &str, pairs: &[(&str, &str)]) -> CallRecord {
        let mut r = record(server, tool);
        r.canonical_subset = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        r
    }

    fn cfg(toml: &str) -> Config {
        Config::from_toml_str(toml).expect("test config must be valid")
    }

    #[test]
    fn suggests_uncovered_and_skips_covered() {
        let config = cfg(
            "[servers.github]\ncommand = \"x\"\n[servers.qdrant]\ncommand = \"y\"\n[[policy.allow]]\nsig = \"github__*\"\n",
        );
        let records = vec![
            record("github", "create_issue"), // покрыт wildcard-правилом
            record("qdrant", "search"),
            record("qdrant", "search"), // дубликат схлопывается
            record("qdrant", "upsert"),
        ];
        let out = suggest(&records, &config);
        assert_eq!(out.sigs(), vec!["qdrant__search", "qdrant__upsert"]);
        assert!(out.toml_snippet.contains("sig = \"qdrant__search\""));
        assert!(!out.toml_snippet.contains("github"));
        assert!(out
            .client_allow_snippet
            .contains("mcp__zastava__qdrant__search"));
    }

    #[test]
    fn single_observed_value_becomes_an_exact_matcher() {
        let config = cfg("[servers.github]\ncommand = \"x\"\n");
        let records = vec![
            with_subset("github", "create_issue", &[("repo", "me/zastava")]),
            with_subset("github", "create_issue", &[("repo", "me/zastava")]),
        ];
        let out = suggest(&records, &config);
        let proposal = &out.proposals[0];
        assert!(proposal.is_narrowed(), "правило обязано сузиться по repo");
        assert_eq!(proposal.calls, 2);
        assert_eq!(
            proposal.args.as_ref().unwrap()["repo"],
            ArgMatcher::Exact("me/zastava".into())
        );
        assert!(out.toml_snippet.contains("repo"), "{}", out.toml_snippet);
    }

    #[test]
    fn a_few_values_become_any_of_many_are_dropped() {
        let config = cfg("[servers.github]\ncommand = \"x\"\n");
        let few: Vec<CallRecord> = ["me/a", "me/b"]
            .iter()
            .map(|repo| with_subset("github", "issue", &[("repo", repo)]))
            .collect();
        let out = suggest(&few, &config);
        assert_eq!(
            out.proposals[0].args.as_ref().unwrap()["repo"],
            ArgMatcher::AnyOf(AnyOfMatcher {
                any_of: vec!["me/a".into(), "me/b".into()]
            })
        );

        let many: Vec<CallRecord> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|repo| with_subset("github", "issue", &[("repo", repo)]))
            .collect();
        let out = suggest(&many, &config);
        assert!(
            !out.proposals[0].is_narrowed(),
            "разнообразие значений не сужает доступ, правило остаётся tool-level"
        );
    }

    #[test]
    fn truncated_path_becomes_a_prefix_rule_that_matches_the_raw_argument() {
        // Ровно тот мост, ради которого learn существует: в журнале лежит
        // усечённый путь, а правило обязано совпасть с сырым аргументом.
        let config = cfg("[servers.fs]\ncommand = \"x\"\n");
        let out = suggest(
            &[with_subset("fs", "read", &[("path", "C:/work/zastava/…")])],
            &config,
        );
        let matcher = out.proposals[0].args.as_ref().unwrap()["path"].clone();
        assert_eq!(
            matcher,
            ArgMatcher::Prefix(PrefixMatcher {
                prefix: "C:/work/zastava".into()
            })
        );
        assert!(
            matcher.matches(&serde_json::json!("C:\\work\\zastava\\src\\main.rs")),
            "правило обязано совпадать с сырым windows-путём"
        );
        assert!(!matcher.matches(&serde_json::json!("C:/other/secret.txt")));
    }

    #[test]
    fn key_missing_from_some_calls_is_not_required() {
        // Иначе правило молча отсечёт законные вызовы без этого ключа.
        let config = cfg("[servers.a]\ncommand = \"x\"\n");
        let out = suggest(
            &[with_subset("a", "t", &[("repo", "me/x")]), record("a", "t")],
            &config,
        );
        assert!(
            !out.proposals[0].is_narrowed(),
            "необязательный ключ не должен становиться требованием"
        );
    }

    #[test]
    fn generated_argument_rule_is_a_valid_config_and_actually_enforces() {
        // Сниппет обязан не просто парситься, а работать как заявлено.
        let base = "[servers.github]\ncommand = \"x\"\n[policy]\nmode = \"enforce\"\n";
        let out = suggest(
            &[with_subset(
                "github",
                "create_issue",
                &[("repo", "me/mine")],
            )],
            &cfg(base),
        );
        let merged = format!("{base}{}", out.toml_snippet);
        let parsed = cfg(&merged);
        let engine = PolicyEngine::from_config(&parsed.policy);

        let mine = serde_json::json!({"repo": "me/mine"});
        let theirs = serde_json::json!({"repo": "victim/repo"});
        assert_eq!(
            engine
                .decide("github", "create_issue", mine.as_object().unwrap())
                .verdict,
            crate::Verdict::Allow
        );
        assert!(
            engine
                .decide("github", "create_issue", theirs.as_object().unwrap())
                .blocks(),
            "сгенерированное правило обязано реально сужать доступ"
        );
    }

    #[test]
    fn never_suggests_rule_that_widens_an_argument_rule() {
        // Находка ревью M1 (обе линзы независимо): tool-level предложение
        // поверх правила с args сняло бы сужение по repo.
        let config = cfg(
            "[servers.github]\ncommand = \"x\"\n[[policy.allow]]\nsig = \"github__create_issue\"\nargs = { repo = \"safe/repo\" }\n",
        );
        let out = suggest(&[record("github", "create_issue")], &config);
        assert!(
            out.proposals.is_empty(),
            "предлагать tool-level поверх аргументного правила нельзя: {:?}",
            out.sigs()
        );
        assert_eq!(out.narrowed.len(), 1);
        assert!(out.narrowed[0].contains("github__create_issue"));
    }

    #[test]
    fn foreign_servers_are_reported_not_suggested() {
        // Журнал общий на машину: сервер другого проекта не должен попадать
        // в черновик, иначе вставка ломает конфиг (unknown server).
        let config = cfg("[servers.a]\ncommand = \"x\"\n");
        let out = suggest(&[record("qdrant", "search"), record("a", "ping")], &config);
        assert_eq!(out.sigs(), vec!["a__ping"]);
        assert_eq!(out.foreign, vec!["qdrant__search"]);
    }

    #[test]
    fn markers_are_skipped() {
        let config = cfg("[servers.a]\ncommand = \"x\"\n");
        let marker = CallRecord::marker("t".into(), "id".into(), "audit_disabled", None);
        let out = suggest(&[marker], &config);
        assert!(out.proposals.is_empty());
    }

    #[test]
    fn hostile_tool_name_never_reaches_a_snippet() {
        // P1 верификации фиксов M1, воспроизведён end-to-end: имя инструмента
        // выбирает downstream, а сниппет пользователь копирует в конфиг.
        let config = cfg("[servers.evil]\ncommand = \"x\"\n");
        let payload = "ping\"\n\n[[policy.allow]]\nsig = \"alpha__*\"\n#";
        let out = suggest(&[record("evil", payload)], &config);
        assert!(out.proposals.is_empty(), "враждебное имя не предлагается");
        assert!(
            !out.toml_snippet.contains("alpha__*"),
            "чужое правило не должно попасть в сниппет: {}",
            out.toml_snippet
        );
        assert_eq!(out.suspicious.len(), 1);
        assert!(
            !out.suspicious[0].contains('\n') && !out.suspicious[0].contains('\"'),
            "показываем экранированным: {}",
            out.suspicious[0]
        );
    }

    #[test]
    fn hostile_argument_value_never_reaches_a_snippet() {
        // Второй сток той же инъекции: имя инструмента отфильтровано, но
        // ЗНАЧЕНИЕ аргумента тоже приходит снаружи и тоже печатается.
        let config = cfg("[servers.a]\ncommand = \"x\"\n");
        let out = suggest(
            &[with_subset(
                "a",
                "t",
                &[("repo", "ok\"\n\n[[policy.allow]]\nsig = \"a__*\"\n#")],
            )],
            &config,
        );
        let merged = format!("[servers.a]\ncommand = \"x\"\n{}", out.toml_snippet);
        let parsed = cfg(&merged);
        assert_eq!(
            parsed.policy.allow.len(),
            1,
            "инъекция дописала правило: {}",
            out.toml_snippet
        );
        assert_eq!(parsed.policy.allow[0].sig, "a__t");
    }

    #[test]
    fn snippets_are_machine_parseable() {
        let config = cfg("[servers.a]\ncommand = \"x\"\n");
        let out = suggest(&[record("a", "ping")], &config);
        // TOML-сниппет обязан разбираться как валидный конфиг-фрагмент.
        let parsed = cfg(&format!(
            "[servers.a]
command = \"x\"
{}",
            out.toml_snippet
        ));
        assert_eq!(parsed.policy.allow[0].sig, "a__ping");
        // JSON-сниппет — как валидный JSON.
        let json: serde_json::Value =
            serde_json::from_str(&out.client_allow_snippet).expect("valid json");
        assert_eq!(json["permissions"]["allow"][0], "mcp__zastava__a__ping");
    }

    #[test]
    fn empty_log_yields_empty_output() {
        let config = cfg("[servers.a]\ncommand = \"x\"\n");
        let out = suggest(&[], &config);
        assert!(out.proposals.is_empty());
        assert!(out.toml_snippet.is_empty());
        assert!(out.client_allow_snippet.is_empty());
    }
}

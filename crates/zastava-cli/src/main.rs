//! CLI Заставы. В режиме `run` stdout принадлежит JSON-RPC эксклюзивно —
//! вся диагностика (tracing) уходит в stderr; обычный вывод команд вроде
//! `check`/`stats` пишется в stdout только вне `run`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use zastava_core::config::{
    is_safe_sig, parse_sig, ArgMatcher, DefaultAction, PolicyMode, ServerConfig, NS_SEP,
};
use zastava_core::Config;

/// Обёртка для сериализации импортированных серверов в TOML.
///
/// Импорт собирает документ ЧЕРЕЗ СЕРИАЛИЗАТОР, а не склейкой строк: ключи и
/// значения из `.claude.json` недоверенные, и склейка позволяла ключу env
/// закрыть inline-таблицу и дописать собственную секцию `[policy]`
/// (воспроизведено на ревью M1 — импорт молча выключал enforce).
#[derive(serde::Serialize)]
struct ImportDoc {
    servers: BTreeMap<String, ServerConfig>,
}

#[derive(Parser)]
#[command(
    name = "zastava",
    version,
    about = "MCP-гейтвей: аргументные политики, аудит-лог, learn"
)]
struct Cli {
    /// Путь к zastava.toml (по умолчанию — конфиг-директория ОС).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Проверить конфиг и показать план политик (fail-closed: невалидный конфиг = exit 1).
    Check,
    /// Запустить гейтвей (stdio MCP-сервер) до EOF клиента.
    Run {
        /// Прозрачный режим: политика не применяется. Журнал ПРОДОЛЖАЕТ
        /// вестись и помечается маркером policy_disabled — отключение
        /// контроля обязано оставлять след. Также включается переменной
        /// окружения ZASTAVA_DISABLE=1.
        #[arg(long)]
        passthrough: bool,
    },
    /// Сводка по журналу вызовов (+ baseline-счётчик промптов, если есть).
    Stats,
    /// Добавить tool-level allow-правило в конфиг (работающий гейтвей
    /// подхватит без рестарта через file-watch).
    Allow {
        /// Сигнатура: <server>__<tool> или <server>__*.
        sig: String,
        /// Добавить, даже если правило снимает существующее аргументное
        /// сужение (по умолчанию такое отклоняется).
        #[arg(long)]
        force: bool,
    },
    /// Последние события журнала с их идентификаторами — то, чем потом
    /// пользуется `annotate`.
    Events {
        /// Сколько последних событий показать.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Только отказы (deny/rejected).
        #[arg(long)]
        denied: bool,
    },
    /// Черновики правил из журнала: TOML для zastava.toml + сниппет
    /// клиентского permissions.allow.
    Learn,
    /// Отметить событие журнала как полезное или ложное — в момент события,
    /// пока помнишь контекст.
    Annotate {
        /// Идентификатор события из журнала (колонка id).
        event_id: String,
        /// Заметка: чем срабатывание помогло или почему оно ложное.
        note: String,
    },
    /// Импортировать stdio-серверы из .claude.json в zastava.toml.
    Import {
        /// Путь к .claude.json (по умолчанию — домашняя директория).
        #[arg(long)]
        from: Option<PathBuf>,
        /// Перезаписать существующий zastava.toml.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.as_deref());

    match cli.command {
        Command::Check => check(&config_path),
        Command::Run { passthrough } => run(&config_path, passthrough),
        Command::Stats => stats(&config_path),
        Command::Allow { sig, force } => allow(&config_path, &sig, force),
        Command::Events { limit, denied } => events(&config_path, limit, denied),
        Command::Learn => learn(&config_path),
        Command::Annotate { event_id, note } => annotate(&config_path, &event_id, &note),
        Command::Import { from, force } => import(&config_path, from.as_deref(), force),
    }
}

/// Явный --config побеждает; иначе — конфиг-директория ОС
/// (%APPDATA%\zastava на Windows, ~/.config/zastava на Linux/macOS).
fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("zastava")
            .join("zastava.toml"),
    }
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    let raw = std::fs::read_to_string(path).with_context(|| {
        if path.exists() {
            format!("cannot read config: {}", path.display())
        } else {
            // Пустая ошибка ОС на первом же шаге — тупик: человек не знает
            // ни где должен лежать файл, ни как его создать.
            format!(
                "конфига нет: {}
Создай его импортом из клиента: zastava import",
                path.display()
            )
        }
    })?;
    Config::from_toml_str(&raw).with_context(|| format!("invalid config: {}", path.display()))
}

/// Путь журнала: config.log.path побеждает; иначе — data-директория ОС.
fn resolve_log_path(config: &Config) -> PathBuf {
    match &config.log.path {
        Some(path) => PathBuf::from(path),
        None => dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("zastava")
            .join("calls.jsonl"),
    }
}

fn check(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    println!("Config OK: {}", path.display());
    println!(
        "  servers: {} ({})",
        config.servers.len(),
        config
            .servers
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  policy:  mode={} default={} rules={}",
        mode_name(config.policy.mode),
        default_name(config.policy.default),
        config.policy.allow.len()
    );
    // Дефолт — warn, и в нём НИЧЕГО не блокируется. Слово `deny` рядом с ним
    // успокаивает ровно тогда, когда защиты нет: продуктовое ревью M3 прошло
    // сценарий целиком и вышло из него с ложным чувством защищённости.
    if config.policy.mode == PolicyMode::Warn {
        println!("           ⚠ warn: вызовы НЕ блокируются, вердикты только пишутся в журнал.");
        println!("             Когда правила обкатаются — mode = \"enforce\".");
    }
    for rule in &config.policy.allow {
        match &rule.args {
            Some(args) => {
                let narrowing = args
                    .iter()
                    .map(|(key, matcher)| format!("{key} {}", describe_matcher(matcher)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let strict = if rule.deny_extra_args {
                    ", без прочих аргументов"
                } else {
                    ""
                };
                println!("    allow {}  ({narrowing}{strict})", rule.sig);
            }
            None => println!("    allow {}  (tool-level)", rule.sig),
        }
    }
    // Затенённое правило выглядит в конфиге живым, но не действует. Молчать
    // об этом нельзя: `zastava allow <server>__*` дописывает правило в конец
    // и снимает все аргументные сужения выше (P1 ревью M3).
    let engine = zastava_core::PolicyEngine::from_config(&config.policy);
    let defeated = engine.defeated_narrowings();
    if !defeated.is_empty() {
        println!();
        println!("  ⛔ СУЖЕНИЕ НЕ ДЕЙСТВУЕТ — правило ниже пропускает то, что узкое отклонило:");
        for (narrow, by) in &defeated {
            println!("     {narrow} снято правилом {by}");
        }
        println!("     Убери широкое правило или подними узкое выше него.");
        println!();
    }
    // Что именно уедет в журнал открыто — вопрос приватности, и ответ на него
    // должен быть виден до первого вызова, а не после разбора инцидента.
    if !config.canon.extra_keys.is_empty() || !config.canon.deny_keys.is_empty() {
        println!(
            "  canon:   +[{}] -[{}] поверх дефолтного whitelist",
            config.canon.extra_keys.join(", "),
            config.canon.deny_keys.join(", ")
        );
    }
    for rule in &config.canon.rules {
        println!("    canon {} → [{}]", rule.sig, rule.keys.join(", "));
    }
    println!("  log:     {}", resolve_log_path(&config).display());
    if config.log.log_args {
        println!("  WARNING log_args = true: в журнал пишутся ПОЛНЫЕ аргументы вызовов;");
        println!("          до маскировки секретов (M4) туда попадут и токены.");
    }
    Ok(())
}

fn run(path: &Path, passthrough_flag: bool) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let passthrough = passthrough_flag
        || std::env::var("ZASTAVA_DISABLE")
            .map(|v| v == "1")
            .unwrap_or(false);
    let options = zastava_proxy::RunOptions {
        passthrough,
        log_path: Some(resolve_log_path(&config)),
        config_path: Some(path.to_path_buf()),
    };
    let runtime = tokio::runtime::Runtime::new().context("tokio runtime")?;
    runtime
        .block_on(zastava_proxy::run(config, options))
        .context("gateway failed")
}

/// Читает журнал, различая «журнала нет» и «журнал не читается».
///
/// Для инструмента, чей продукт — доказательство происходившего, отсутствие
/// файла и пустая история обязаны выглядеть по-разному, а ошибка чтения не
/// должна маскироваться под «вызовов не было» (находка ревью M1).
fn read_journal(log_path: &Path) -> anyhow::Result<Option<Vec<zastava_core::CallRecord>>> {
    Ok(read_journal_counted(log_path)?.map(|(records, _)| records))
}

/// То же, но с числом строк, которые не удалось прочитать.
fn read_journal_counted(
    log_path: &Path,
) -> anyhow::Result<Option<(Vec<zastava_core::CallRecord>, usize)>> {
    // Читаем вместе с отротированными поколениями: иначе после первой же
    // ротации история для пользователя начиналась с нуля.
    match zastava_proxy::logger::read_all_generations_counted(log_path) {
        Ok(found) => Ok(Some(found)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read journal: {}", log_path.display())),
    }
}

/// Показывает хвост журнала.
///
/// Без неё `annotate <event_id>` было нечем пользоваться: идентификатор
/// существовал только внутри JSONL-файла, и справка предлагала пользователю
/// открыть его руками (находка продуктового ревью M3).
fn events(path: &Path, limit: usize, denied_only: bool) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let log_path = resolve_log_path(&config);
    let Some(records) = read_journal(&log_path)? else {
        println!("Журнал ещё не создан: {}", log_path.display());
        return Ok(());
    };

    let selected: Vec<&zastava_core::CallRecord> = records
        .iter()
        .filter(|r| !denied_only || r.decision == "deny" || r.decision == "rejected")
        .rev()
        .take(limit)
        .collect();
    if selected.is_empty() {
        println!("Подходящих событий в журнале нет.");
        return Ok(());
    }
    println!("{:<24} {:<20} {:<10} ЧТО", "ID", "ВРЕМЯ", "РЕШЕНИЕ");
    for record in selected.iter().rev() {
        let what = if record.is_call() {
            format!("{}{}{}", record.server, NS_SEP, record.tool)
        } else {
            format!("[событие] {}", record.tool)
        };
        let decision = if record.is_call() {
            let blocked = if record.decision == "deny" && !record.enforced {
                "deny(warn)"
            } else {
                record.decision.as_str()
            };
            blocked.to_string()
        } else {
            "-".to_string()
        };
        println!(
            "{:<24} {:<20} {:<10} {}",
            record.id,
            record.ts.chars().take(19).collect::<String>(),
            decision,
            what
        );
    }
    println!();
    println!("Отметить событие: zastava annotate <ID> \"чем помогло или почему ложное\"");
    Ok(())
}

fn stats(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let log_path = resolve_log_path(&config);
    let Some((records, unreadable)) = read_journal_counted(&log_path)? else {
        println!("Журнал ещё не создан: {}", log_path.display());
        println!("(это НЕ то же самое, что «вызовов не было»)");
        return Ok(());
    };
    let mut summary = zastava_core::stats::summarize(&records);
    summary.unreadable_lines = unreadable as u64;

    println!("Журнал: {}", log_path.display());
    println!("  вызовов:            {}", summary.total);
    println!("  уникальных сигнатур: {}", summary.unique_sigs);
    match summary.repeat_ratio() {
        Some(ratio) => println!(
            "  повторов (M/N):      {} ({:.0}%)",
            summary.repeats,
            ratio * 100.0
        ),
        None => println!("  повторов (M/N):      —"),
    }
    println!("  deny-вердиктов:      {}", summary.denies);
    // Вердикт и блокировка — разные вещи, и в warn-режиме второе всегда ноль.
    // Пользователь, читающий «deny-вердиктов: 847», иначе уверен, что его 847
    // раз прикрыли (находка продуктового ревью M3).
    println!(
        "  из них заблокировано: {}{}",
        summary.blocked,
        if summary.denies > 0 && summary.blocked == 0 {
            "  ← warn-режим: не заблокировано НИ ОДНОГО"
        } else {
            ""
        }
    );
    println!("  ошибок/таймаутов:    {}", summary.errors);
    if summary.legacy_calls > 0 {
        println!(
            "  записей прошлых версий: {} (аргументы в них не сохранялись — learn их не учитывает)",
            summary.legacy_calls
        );
    }
    if summary.unreadable_lines > 0 {
        println!(
            "  ⚠ НЕЧИТАЕМЫХ строк:  {} — журнал повреждён, часть истории потеряна",
            summary.unreadable_lines
        );
    }
    if summary.abandoned > 0 {
        println!(
            "  брошено по таймауту: {} (побочный эффект мог состояться)",
            summary.abandoned
        );
    }
    if summary.annotations > 0 {
        println!("  заметок annotate:    {}", summary.annotations);
    }
    if summary.weakenings > 0 {
        println!(
            "  ОСЛАБЛЕНИЙ политики: {} (см. маркеры policy_weakened в журнале)",
            summary.weakenings
        );
    }
    if summary.markers > 0 {
        println!("  событий гейтвея:     {}", summary.markers);
    }
    for (server, count) in &summary.per_server {
        println!("    {server}: {count}");
    }

    let baseline = dirs::home_dir()
        .unwrap_or_default()
        .join(".zastava")
        .join("baseline.jsonl");
    if let Ok(content) = std::fs::read_to_string(&baseline) {
        println!(
            "Baseline-промптов (hook): {} — {}",
            content.lines().count(),
            baseline.display()
        );
    }
    Ok(())
}

fn allow(path: &Path, sig: &str, force: bool) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let parsed = parse_sig(sig).with_context(|| {
        format!("malformed sig '{sig}': expected <server>__<tool> or <server>__*")
    })?;
    // Строгий charset — именно на пути ЗАПИСИ: сигнатура уходит в TOML-файл,
    // и кавычка с переводом строки там означала бы дописанные правила
    // (воспроизведено на ревью M1). Разбор существующего конфига при этом
    // остаётся терпимым, иначе гейтвей не стартовал бы на чужих именах.
    if !is_safe_sig(sig) {
        bail!("unsafe characters in sig '{sig}': allowed set is [A-Za-z0-9_.-] plus '__' and '*'");
    }
    if !config.servers.contains_key(parsed.server) {
        bail!(
            "unknown server '{}' (known: {})",
            parsed.server,
            config
                .servers
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if config.policy.allow.iter().any(|rule| rule.sig == sig) {
        println!("Правило уже есть: {sig}");
        return Ok(());
    }

    // Правило дописывается в КОНЕЦ, а выигрывает первое подошедшее — значит
    // широкое правило снимает все аргументные сужения выше. Продуктовое ревью
    // M3 прошло это вживую: `zastava allow echo__*` открыл доступ в ~/.ssh,
    // а `check` продолжал показывать узкое правило действующим.
    let mut probe = config.policy.clone();
    probe.allow.push(zastava_core::config::RuleConfig {
        sig: sig.to_string(),
        args: None,
        deny_extra_args: false,
    });
    let probe_engine = zastava_core::PolicyEngine::from_config(&probe);
    let defeated = probe_engine.defeated_narrowings();
    if !defeated.is_empty() && !force {
        let list = defeated
            .iter()
            .map(|(narrow, _)| *narrow)
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "правило '{sig}' снимет аргументное сужение: {list}
             Оно шире и стоит ниже, поэтому пропустит всё, что узкое отклоняет.
             Если это осознанно — повтори с --force."
        );
    }

    // Дописывание блока в конец, а не round-trip через сериализатор:
    // комментарии и форматирование пользователя остаются байт в байт.
    // Работающий гейтвей подхватит файл через watcher без рестарта сессии.
    let mut raw = std::fs::read_to_string(path)?;
    if !raw.ends_with('\n') {
        raw.push('\n');
    }
    raw.push_str(&format!("\n[[policy.allow]]\nsig = \"{sig}\"\n"));
    Config::from_toml_str(&raw).context("internal: appended config became invalid")?;
    write_atomic(path, &raw)?;
    println!("Добавлено allow-правило: {sig}");
    Ok(())
}

fn learn(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let log_path = resolve_log_path(&config);
    let Some(records) = read_journal(&log_path)? else {
        println!("Журнал ещё не создан: {}", log_path.display());
        return Ok(());
    };
    let output = zastava_core::learn::suggest(&records, &config);

    if !output.suspicious.is_empty() {
        println!("# ⛔ Имена с недопустимыми символами — в правила НЕ предлагаются");
        println!("#    (имя инструмента выбирает downstream; показано экранированным):");
        for sig in &output.suspicious {
            println!("#   {sig}");
        }
        println!();
    }
    if !output.narrowed.is_empty() {
        println!("# ⚠ Уже под аргументным правилом — расширять только осознанно:");
        for sig in &output.narrowed {
            println!("#   {sig}");
        }
        println!();
    }
    if !output.foreign.is_empty() {
        println!("# ℹ Из журнала, но не из этого конфига (журнал общий на машину):");
        for sig in &output.foreign {
            println!("#   {sig}");
        }
        println!();
    }
    if output.proposals.is_empty() {
        // «Журнал пуст» и «всё уже покрыто» — разные состояния, и советы у
        // них разные (находка продуктового ревью M3).
        if records.iter().all(|r| !r.is_call()) {
            println!("В журнале ещё нет вызовов — поработай через заставу, потом возвращайся.");
        } else {
            println!("Непокрытых сигнатур для этого конфига нет — предлагать нечего.");
        }
        return Ok(());
    }
    println!(
        "# Непокрытые сигнатуры из журнала ({}):",
        output.proposals.len()
    );
    for proposal in &output.proposals {
        let calls = proposal.calls;
        match &proposal.args {
            Some(args) => {
                let narrowing = args
                    .iter()
                    .map(|(key, matcher)| format!("{key} {}", describe_matcher(matcher)))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "#   {} — {calls} вызов(ов), сужено: {narrowing}",
                    proposal.sig
                );
            }
            None => println!(
                "#   {} — {calls} вызов(ов), сузить по аргументам нечем",
                proposal.sig
            ),
        }
        if proposal.legacy_calls > 0 {
            println!(
                "#     (+{} записей прошлых версий заставы — аргументы в них не сохранялись)",
                proposal.legacy_calls
            );
        }
    }
    println!();
    println!("# --- в zastava.toml (вычеркни лишнее): ---");
    println!("{}", output.toml_snippet);
    if output.proposals.iter().any(|p| p.is_narrowed()) && config.policy.mode == PolicyMode::Warn {
        println!(
            "# ℹ mode = \"warn\": новые правила пока только пишутся в журнал.\n\
             #   Поживи с ними неделю, проверь `zastava stats`, потом mode = \"enforce\"."
        );
        println!();
    }
    println!("# --- в settings.json клиента (per-tool через заставу): ---");
    println!("{}", output.client_allow_snippet);
    Ok(())
}

/// Дописывает в журнал заметку о событии.
///
/// Ценность гейта проверяется не в конце квартала, а в момент срабатывания:
/// «этот deny спас меня от записи в чужой репозиторий» или «этот deny был
/// ложным». Заметка — обычная строка журнала (маркер), поэтому она попадает
/// и в ротацию, и в `stats`, и переживает рестарт.
fn annotate(config_path: &Path, event_id: &str, note: &str) -> anyhow::Result<()> {
    // event_id генерируем мы сами, но приходит он из аргументов командной
    // строки: пускать в журнал произвольную строку нельзя — перевод строки
    // разорвал бы JSONL-запись на две.
    if event_id.is_empty()
        || !event_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("event_id '{event_id}' не похож на идентификатор из журнала");
    }
    if note.trim().is_empty() {
        bail!("пустая заметка");
    }

    let config = load_config(config_path)?;
    let log_path = resolve_log_path(&config);
    let records = match read_journal(&log_path)? {
        Some(records) => records,
        None => bail!("журнала ещё нет: {}", log_path.display()),
    };
    let target = records.iter().find(|r| r.id == event_id);
    let detail = match target {
        Some(record) if record.is_call() => {
            format!("{}__{}: {note}", record.server, record.tool)
        }
        Some(_) => note.to_string(),
        // Не молчим: неизвестный id почти всегда означает опечатку, и
        // заметка «в никуда» хуже отказа — её потом не найти.
        None => bail!(
            "события '{event_id}' нет в журнале {} — проверь id",
            log_path.display()
        ),
    };

    // У заметки СВОЙ идентификатор: две записи с одинаковым id сделали бы
    // журнал неоднозначным, а на аннотируемое событие ссылается текст.
    let record = zastava_core::CallRecord::marker(
        zastava_proxy::util::now_rfc3339(),
        zastava_proxy::util::next_event_id(),
        "annotation",
        Some(format!("{event_id}: {detail}")),
    );
    let line = record.to_jsonl();
    append_line(&log_path, &line)?;
    println!("Записано: {event_id} — {note}");
    Ok(())
}

/// Дописывает строку в журнал тем же способом, что и сам гейтвей: один
/// `write_all` в режиме append. Заставa может работать прямо сейчас, и две
/// строки не должны перемешаться.
fn append_line(path: &Path, line: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open journal {}", path.display()))?;
    let mut buf = line.as_bytes().to_vec();
    buf.push(b'\n');
    file.write_all(&buf)
        .with_context(|| format!("cannot append to journal {}", path.display()))?;
    Ok(())
}

/// Имя режима ровно в том виде, в каком его пишут в конфиг. Debug-формат
/// печатал `Warn`, а конфиг требует `warn` — вывод команды `check` не должен
/// расходиться с тем, что пользователь пойдёт вставлять в файл.
fn mode_name(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Warn => "warn",
        PolicyMode::Enforce => "enforce",
    }
}

fn default_name(action: DefaultAction) -> &'static str {
    match action {
        DefaultAction::Deny => "deny",
        DefaultAction::Allow => "allow",
    }
}

/// Человекочитаемое описание матчера для вывода `learn`.
fn describe_matcher(matcher: &ArgMatcher) -> String {
    match matcher {
        ArgMatcher::Exact(value) => format!("= {value}"),
        ArgMatcher::Prefix(m) => format!("начинается с {}", m.prefix),
        ArgMatcher::AnyOf(m) => format!("одно из [{}]", m.any_of.join(", ")),
    }
}

fn import(config_path: &Path, from: Option<&Path>, force: bool) -> anyhow::Result<()> {
    let claude_json = match from {
        Some(path) => path.to_path_buf(),
        None => dirs::home_dir()
            .context("cannot resolve home dir")?
            .join(".claude.json"),
    };
    let raw = std::fs::read_to_string(&claude_json)
        .with_context(|| format!("cannot read {}", claude_json.display()))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("invalid json: {}", claude_json.display()))?;

    let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) else {
        bail!("{}: no top-level mcpServers object", claude_json.display());
    };

    let mut collected: BTreeMap<String, ServerConfig> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut renamed = Vec::new();
    for (name, entry) in servers {
        let Some(command) = entry.get("command").and_then(|v| v.as_str()) else {
            skipped.push(format!("{name} (не stdio: нет command)"));
            continue;
        };
        // `_` валиден в именах серверов — раньше он тоже заменялся, из-за чего
        // my_server и my-server схлопывались в один ключ (находка ревью M1).
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        if safe_name != *name {
            renamed.push(format!("{name} → {safe_name}"));
        }
        let server = ServerConfig {
            command: command.to_string(),
            args: entry
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            env: entry
                .get("env")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default(),
            cwd: entry
                .get("cwd")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        if let Some(existing) = collected.insert(safe_name.clone(), server) {
            bail!(
                "name collision: two servers map to '{safe_name}' (one runs {:?}); \
                 rename them in {} before importing",
                existing.command,
                claude_json.display()
            );
        }
    }

    if collected.is_empty() {
        bail!(
            "nothing to import: no stdio servers in {}",
            claude_json.display()
        );
    }
    if config_path.exists() && !force {
        bail!(
            "{} already exists (use --force to overwrite)",
            config_path.display()
        );
    }

    let imported = collected.len();
    let toml = toml::to_string_pretty(&ImportDoc { servers: collected })
        .context("serializing imported servers")?;
    Config::from_toml_str(&toml).context("internal: imported config is invalid")?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private(config_path, &toml)?;

    println!(
        "Импортировано серверов: {imported} → {}",
        config_path.display()
    );
    for s in &renamed {
        println!("  переименован: {s}");
    }
    for s in &skipped {
        println!("  пропущен: {s}");
    }
    println!("Дальше: `zastava check`, затем подключи заставу в клиенте.");
    Ok(())
}

/// Записывает файл целиком или не записывает вовсе: сначала во временный
/// файл рядом, затем rename поверх.
///
/// Обычная запись усекает файл и наполняет его заново. Гейтвей в это время
/// следит за конфигом — и обрезанный на середине TOML часто остаётся ВАЛИДНЫМ
/// (если обрыв пришёлся до секции `[policy]`), так что watcher принял бы
/// конфиг без единого правила. Для инструмента, чья работа — применять
/// политику, это худший вид отказа: тихое ослабление.
fn write_atomic(path: &Path, content: &str) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    // Временный файл обязан лежать в той же директории: rename атомарен
    // только внутри одной файловой системы.
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "zastava".to_string())
    ));
    std::fs::write(&tmp, content)
        .with_context(|| format!("cannot write temp file {}", tmp.display()))?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e).with_context(|| format!("cannot replace {}", path.display()))
        }
    }
}

/// Пишет файл с правами только для владельца там, где ОС это умеет.
/// Импорт переносит содержимое `env` (то есть токены) во второй файл —
/// оставлять его с umask-правами нельзя (находка ревью M1).
fn write_private(path: &Path, content: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        // mode() действует только при СОЗДАНИИ: у существующего файла
        // (import --force поверх старого) права надо выставить явно, иначе
        // токены из env остаются читаемыми всем (находка верификации M1).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        // На Windows права наследуются от каталога. Импорт переносит `env`
        // (то есть токены), и молчать об этом нельзя.
        std::fs::write(path, content)?;
        eprintln!(
            "ВНИМАНИЕ: {} содержит переменные окружения серверов (возможно, токены).
             Права файла не сужены — проверь доступ к нему вручную.",
            path.display()
        );
        Ok(())
    }
}

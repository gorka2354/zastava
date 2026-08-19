//! CLI Заставы. В режиме `run` stdout принадлежит JSON-RPC эксклюзивно —
//! вся диагностика (tracing) уходит в stderr; обычный вывод команд вроде
//! `check`/`stats` пишется в stdout только вне `run`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use zastava_core::config::{is_safe_sig, parse_sig, ServerConfig};
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
    },
    /// Черновики правил из журнала: TOML для zastava.toml + сниппет
    /// клиентского permissions.allow.
    Learn,
    /// Отметить срабатывание правила как полезное (в момент события). Появится в M3.
    Annotate {
        /// Идентификатор события из журнала.
        event_id: String,
        /// Почему срабатывание было полезным.
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
        Command::Allow { sig } => allow(&config_path, &sig),
        Command::Learn => learn(&config_path),
        Command::Annotate { .. } => bail!("`zastava annotate` появится в M3"),
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
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config: {}", path.display()))?;
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
        "  policy:  mode={:?} default={:?} rules={}",
        config.policy.mode,
        config.policy.default,
        config.policy.allow.len()
    );
    for rule in &config.policy.allow {
        match &rule.args {
            Some(args) => println!(
                "    allow {}  args{{{}}}",
                rule.sig,
                args.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
            None => println!("    allow {}  (tool-level)", rule.sig),
        }
    }
    println!("  log:     {}", resolve_log_path(&config).display());
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
    // Читаем вместе с отротированными поколениями: иначе после первой же
    // ротации история для пользователя начиналась с нуля.
    match zastava_proxy::logger::read_all_generations(log_path) {
        Ok(records) => Ok(Some(records)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read journal: {}", log_path.display())),
    }
}

fn stats(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let log_path = resolve_log_path(&config);
    let Some(records) = read_journal(&log_path)? else {
        println!("Журнал ещё не создан: {}", log_path.display());
        println!("(это НЕ то же самое, что «вызовов не было»)");
        return Ok(());
    };
    let summary = zastava_core::stats::summarize(&records);

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
    println!("  ошибок/таймаутов:    {}", summary.errors);
    if summary.abandoned > 0 {
        println!(
            "  брошено по таймауту: {} (побочный эффект мог состояться)",
            summary.abandoned
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

fn allow(path: &Path, sig: &str) -> anyhow::Result<()> {
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

    // Простое дописывание блока в конец: комментарии и форматирование юзера
    // не трогаем (toml_edit-полировка — M3). Работающий гейтвей подхватит
    // файл через watcher без рестарта сессии.
    let mut raw = std::fs::read_to_string(path)?;
    if !raw.ends_with('\n') {
        raw.push('\n');
    }
    raw.push_str(&format!("\n[[policy.allow]]\nsig = \"{sig}\"\n"));
    Config::from_toml_str(&raw).context("internal: appended config became invalid")?;
    std::fs::write(path, raw)?;
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
    if output.new_sigs.is_empty() {
        println!("Непокрытых сигнатур для этого конфига нет — предлагать нечего.");
        return Ok(());
    }
    println!(
        "# Непокрытые сигнатуры из журнала ({}):",
        output.new_sigs.len()
    );
    println!("# --- в zastava.toml (вычеркни лишнее): ---");
    println!("{}", output.toml_snippet);
    println!("# --- в settings.json клиента (per-tool через заставу): ---");
    println!("{}", output.client_allow_snippet);
    Ok(())
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
        std::fs::write(path, content)?;
        Ok(())
    }
}

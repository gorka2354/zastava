//! CLI Заставы. В режиме `run` stdout принадлежит JSON-RPC эксклюзивно —
//! вся диагностика (tracing) уходит в stderr; обычный вывод команд вроде
//! `check`/`stats` пишется в stdout только вне `run`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use zastava_core::config::parse_sig;
use zastava_core::Config;

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
        /// Прозрачный режим без политик и журнала — путь отступления.
        /// Также включается переменной окружения ZASTAVA_DISABLE=1.
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

fn stats(path: &Path) -> anyhow::Result<()> {
    let config = load_config(path)?;
    let log_path = resolve_log_path(&config);
    let records = zastava_proxy::logger::read_records(&log_path).unwrap_or_default();
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
    let records = zastava_proxy::logger::read_records(&log_path).unwrap_or_default();
    let output = zastava_core::learn::suggest(&records, &config);

    if output.new_sigs.is_empty() {
        println!("Журнал не содержит непокрытых сигнатур — предлагать нечего.");
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

    let mut toml = String::new();
    let mut imported = 0usize;
    let mut skipped = Vec::new();
    for (name, entry) in servers {
        let Some(command) = entry.get("command").and_then(|v| v.as_str()) else {
            skipped.push(format!("{name} (не stdio: нет command)"));
            continue;
        };
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        toml.push_str(&format!("[servers.{safe_name}]\ncommand = {command:?}\n"));
        if let Some(args) = entry.get("args").and_then(|v| v.as_array()) {
            let list: Vec<String> = args
                .iter()
                .filter_map(|a| a.as_str().map(|s| format!("{s:?}")))
                .collect();
            if !list.is_empty() {
                toml.push_str(&format!("args = [{}]\n", list.join(", ")));
            }
        }
        if let Some(env) = entry.get("env").and_then(|v| v.as_object()) {
            let pairs: Vec<String> = env
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| format!("{k} = {s:?}")))
                .collect();
            if !pairs.is_empty() {
                toml.push_str(&format!("env = {{ {} }}\n", pairs.join(", ")));
            }
        }
        toml.push('\n');
        imported += 1;
    }

    if imported == 0 {
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

    Config::from_toml_str(&toml).context("internal: imported config is invalid")?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, &toml)?;

    println!(
        "Импортировано серверов: {imported} → {}",
        config_path.display()
    );
    for s in &skipped {
        println!("  пропущен: {s}");
    }
    println!("Дальше: `zastava check`, затем подключи заставу в клиенте.");
    Ok(())
}

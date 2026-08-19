//! CLI Заставы. В режиме `run` stdout принадлежит JSON-RPC эксклюзивно —
//! поэтому ВСЯ диагностика (tracing) уходит в stderr, а обычный вывод команд
//! вроде `check` пишется в stdout только вне `run`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
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
    /// Запустить гейтвей (stdio MCP-сервер). Появится в M1.
    Run {
        /// Прозрачный режим без политик и лога — путь отступления.
        #[arg(long)]
        passthrough: bool,
    },
    /// Статистика вызовов из журнала. Появится в M1.
    Stats,
    /// Добавить allow-правило в конфиг (живой подхват через file-watch). Появится в M1.
    Allow {
        /// Сигнатура: <server>__<tool> или <server>__*.
        sig: String,
    },
    /// Отметить срабатывание правила как полезное (в момент события). Появится в M3.
    Annotate {
        /// Идентификатор события из журнала.
        event_id: String,
        /// Почему срабатывание было полезным.
        note: String,
    },
    /// Импортировать серверы из .claude.json в zastava.toml. Появится в M1.
    Import,
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
        Command::Run { .. } => bail!("`zastava run` появится в M1 (см. inc/inc-1-mvp.md)"),
        Command::Stats => bail!("`zastava stats` появится в M1"),
        Command::Allow { .. } => bail!("`zastava allow` появится в M1"),
        Command::Annotate { .. } => bail!("`zastava annotate` появится в M3"),
        Command::Import => bail!("`zastava import` появится в M1"),
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

fn check(path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config: {}", path.display()))?;
    let config = Config::from_toml_str(&raw)
        .with_context(|| format!("invalid config: {}", path.display()))?;

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
    Ok(())
}

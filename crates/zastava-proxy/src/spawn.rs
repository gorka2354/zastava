//! Спавн downstream-серверов и жизненный цикл их процессов.
//!
//! Контракт падения (решение 2A ревью) реализован обёртками process-wrap
//! (той же библиотекой пользуется сам rmcp):
//! - Windows: `JobObject` + `KillOnDrop` → Job с KILL_ON_JOB_CLOSE — ядро
//!   убивает всё дерево при закрытии хендла, что переживает даже panic=abort;
//! - Unix: `ProcessSession` (setsid) — kill бьёт по всей группе, внуки
//!   (npx → node) не сиротеют. (Abort-путь на Unix — известное ограничение:
//!   без pdeathsig дерево переживает SIGKILL родителя; закрывается в M2-full.)
//!
//! Windows-нюанс npx/npm: это .cmd-скрипты, прямой спавн даёт NotFound —
//! ретраим через `cmd /c`.

use std::time::Duration;

use process_wrap::tokio::CommandWrap;
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::ServiceExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use zastava_core::config::ServerConfig;

use crate::downstream::{DownstreamHandler, ListChangedHub, ProgressBridge, UpstreamSlot};
use crate::error::ProxyError;

/// Живое подключение к downstream-серверу. Уборка дерева процессов зашита в
/// транспорт (см. модульный doc): drop сервиса = kill всего дерева.
pub struct Downstream {
    /// Имя сервера из конфига (ключ неймспейса).
    pub name: String,
    /// rmcp-клиент к процессу.
    pub service: RunningService<RoleClient, DownstreamHandler>,
}

/// Запускает downstream и проводит initialize-хендшейк с таймаутом.
pub async fn spawn_downstream(
    name: &str,
    config: &ServerConfig,
    initialize_timeout: Duration,
    upstream: UpstreamSlot,
    progress: ProgressBridge,
    lists: ListChangedHub,
) -> Result<Downstream, ProxyError> {
    let (transport, stderr) = spawn_transport(name, config)?;
    drain_stderr(name, stderr);

    let handler = DownstreamHandler::with_bridges(name, upstream, progress, lists);
    let service = tokio::time::timeout(initialize_timeout, handler.serve(transport))
        .await
        .map_err(|_| ProxyError::InitializeTimeout {
            server: name.to_string(),
            timeout: initialize_timeout,
        })?
        .map_err(|e| ProxyError::Initialize {
            server: name.to_string(),
            message: e.to_string(),
        })?;

    tracing::info!(server = name, "downstream up");
    Ok(Downstream {
        name: name.to_string(),
        service,
    })
}

fn spawn_transport(
    name: &str,
    config: &ServerConfig,
) -> Result<(TokioChildProcess, Option<tokio::process::ChildStderr>), ProxyError> {
    let direct = try_spawn(config, false);
    #[cfg(windows)]
    let direct = match direct {
        // npx/npm/любой .cmd на Windows нельзя спавнить напрямую. Матчим
        // ErrorKind, а НЕ текст ошибки: текст локализован, и на русской
        // Windows путь к npx.cmd давал «Системе не удается найти указанный
        // путь», мимо прежней проверки `contains("not found")`.
        Err(e) if needs_cmd_shim(&e, config) => {
            tracing::debug!(server = name, error = %e, "direct spawn failed; retrying via cmd /c");
            try_spawn(config, true)
        }
        other => other,
    };
    direct.map_err(|e| ProxyError::Spawn {
        server: name.to_string(),
        message: e.to_string(),
    })
}

/// Стоит ли повторить запуск через `cmd /c`: файл не найден (в т.ч. из-за
/// того, что это скрипт-обёртка) либо команда — явный .cmd/.bat.
#[cfg(windows)]
fn needs_cmd_shim(error: &std::io::Error, config: &ServerConfig) -> bool {
    use std::io::ErrorKind;
    let script_ext = {
        let lower = config.command.to_ascii_lowercase();
        lower.ends_with(".cmd") || lower.ends_with(".bat")
    };
    script_ext
        || matches!(
            error.kind(),
            ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::InvalidInput
        )
}

fn try_spawn(
    config: &ServerConfig,
    via_cmd: bool,
) -> std::io::Result<(TokioChildProcess, Option<tokio::process::ChildStderr>)> {
    let mut cmd = if via_cmd {
        let mut c = Command::new("cmd");
        c.arg("/c").arg(&config.command).args(&config.args);
        c
    } else {
        let mut c = Command::new(&config.command);
        c.args(&config.args);
        c
    };
    cmd.envs(&config.env);
    if let Some(cwd) = &config.cwd {
        cmd.current_dir(cwd);
    }

    let mut wrap = CommandWrap::from(cmd);
    #[cfg(windows)]
    {
        wrap.wrap(process_wrap::tokio::KillOnDrop);
        wrap.wrap(process_wrap::tokio::JobObject);
    }
    #[cfg(unix)]
    {
        wrap.wrap(process_wrap::tokio::ProcessSession);
    }

    TokioChildProcess::builder(wrap)
        .stderr(std::process::Stdio::piped())
        .spawn()
}

/// Дренаж stderr ребёнка (T6.8): не читаешь пайп → child виснет на полном
/// буфере. Всё уходит в tracing (stderr прокси), stdout не трогаем — он
/// принадлежит JSON-RPC.
///
/// Читаем БАЙТАМИ и декодируем lossy: `lines()` отдаёт `InvalidData` на
/// невалидном UTF-8 (на русской Windows `cmd` пишет в OEM-кодировке), и
/// прежний `while let Ok(Some(..))` на этом молча выходил из цикла — пайп
/// переставал читаться, и ребёнок повисал ровно так, как эта функция обязана
/// предотвращать (находка ревью M1).
///
/// Уровень: строки с признаками ошибки — `warn` (иначе падение downstream
/// невидимо при дефолтном фильтре `info`), остальное — `debug`, чтобы тела
/// запросов и токены из болтливых серверов не оседали в логах клиента.
fn drain_stderr(name: &str, stderr: Option<tokio::process::ChildStderr>) {
    const MAX_LINE: usize = 512;
    let Some(stderr) = stderr else { return };
    let server = name.to_string();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    let decoded = String::from_utf8_lossy(&buf);
                    let line = decoded.trim_end();
                    if line.is_empty() {
                        continue;
                    }
                    let mut shown: String = line.chars().take(MAX_LINE).collect();
                    if line.chars().count() > MAX_LINE {
                        shown.push('…');
                    }
                    let lower = shown.to_lowercase();
                    if lower.contains("error") || lower.contains("panic") || lower.contains("fatal")
                    {
                        tracing::warn!(target: "downstream", server = %server, "{shown}");
                    } else {
                        tracing::debug!(target: "downstream", server = %server, "{shown}");
                    }
                }
                Err(e) => {
                    tracing::debug!(target: "downstream", server = %server, error = %e, "stderr closed");
                    break;
                }
            }
        }
    });
}

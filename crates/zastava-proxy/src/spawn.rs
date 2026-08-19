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

use crate::error::ProxyError;

/// Живое подключение к downstream-серверу. Уборка дерева процессов зашита в
/// транспорт (см. модульный doc): drop сервиса = kill всего дерева.
pub struct Downstream {
    /// Имя сервера из конфига (ключ неймспейса).
    pub name: String,
    /// rmcp-клиент к процессу.
    pub service: RunningService<RoleClient, ()>,
}

/// Запускает downstream и проводит initialize-хендшейк с таймаутом.
pub async fn spawn_downstream(
    name: &str,
    config: &ServerConfig,
    initialize_timeout: Duration,
) -> Result<Downstream, ProxyError> {
    let (transport, stderr) = spawn_transport(name, config)?;
    drain_stderr(name, stderr);

    let service = tokio::time::timeout(initialize_timeout, ().serve(transport))
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
    match try_spawn(name, config, false) {
        Ok(ok) => Ok(ok),
        // npx/npm на Windows — .cmd: прямой спавн даёт NotFound.
        #[cfg(windows)]
        Err(ProxyError::Spawn { ref message, .. }) if message.contains("not found") => {
            tracing::debug!(server = name, "direct spawn failed, retrying via cmd /c");
            try_spawn(name, config, true)
        }
        Err(e) => Err(e),
    }
}

fn try_spawn(
    name: &str,
    config: &ServerConfig,
    via_cmd: bool,
) -> Result<(TokioChildProcess, Option<tokio::process::ChildStderr>), ProxyError> {
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
        .map_err(|e| ProxyError::Spawn {
            server: name.to_string(),
            message: e.to_string(),
        })
}

/// Дренаж stderr ребёнка (T6.8): не читаешь пайп → child виснет на полном
/// буфере. Всё уходит в tracing (stderr прокси), stdout не трогаем — он
/// принадлежит JSON-RPC.
fn drain_stderr(name: &str, stderr: Option<tokio::process::ChildStderr>) {
    let Some(stderr) = stderr else { return };
    let server = name.to_string();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(target: "downstream", server = %server, "{line}");
        }
    });
}

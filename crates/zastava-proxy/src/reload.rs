//! Живой reload политик (решение 3A ревью): гейтвей следит за zastava.toml,
//! `zastava allow` просто правит файл — подхват без разрыва MCP-сессии.
//!
//! Fail-safe: невалидный новый конфиг → остаёмся на старой политике + громкая
//! ошибка в stderr. Полировка (debounce, atomic rename, toml_edit) — M3.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use notify::{Event, RecursiveMode, Watcher};
use zastava_core::{Config, PolicyEngine};

/// Держатель watcher'а: Drop останавливает наблюдение.
pub struct WatchGuard {
    _watcher: notify::RecommendedWatcher,
}

/// Вешает наблюдение на файл конфига. Меняется только политика — состав
/// downstream-серверов фиксируется на старте (плановое ограничение M1).
pub fn watch(
    config_path: PathBuf,
    policy: Arc<RwLock<PolicyEngine>>,
) -> notify::Result<WatchGuard> {
    // Следим за директорией: редакторы часто пишут через rename, и watch
    // на сам файл после этого слепнет.
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let file_name = config_path.file_name().map(|n| n.to_os_string());

    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let Ok(event) = result else { return };
        let ours = event
            .paths
            .iter()
            .any(|p| p.file_name().map(|n| n.to_os_string()) == file_name);
        if !ours {
            return;
        }
        reload(&config_path, &policy);
    })?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    Ok(WatchGuard { _watcher: watcher })
}

fn reload(config_path: &Path, policy: &Arc<RwLock<PolicyEngine>>) {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::error!(error = %e, "config unreadable on reload; keeping old policy");
            return;
        }
    };
    match Config::from_toml_str(&raw) {
        Ok(config) => {
            *policy.write().expect("policy lock poisoned") =
                PolicyEngine::from_config(&config.policy);
            tracing::info!(rules = config.policy.allow.len(), mode = ?config.policy.mode, "policy reloaded");
        }
        Err(e) => {
            tracing::error!(error = %e, "invalid config on reload; keeping old policy");
        }
    }
}

//! Живой reload политик (решение 3A ревью): гейтвей следит за zastava.toml,
//! `zastava allow` просто правит файл — подхват без разрыва MCP-сессии.
//!
//! Fail-safe: невалидный новый конфиг → остаёмся на старой политике + громкая
//! ошибка в stderr.
//!
//! Два неочевидных требования, которые здесь и решаются:
//! 1. **Debounce.** Сохранение файла редактором — это несколько событий, и
//!    часть из них приходит на ЧАСТИЧНО записанный файл. Обрезанный TOML
//!    нередко остаётся валидным (обрыв до секции `[policy]`), так что без
//!    паузы гейтвей мог бы принять конфиг без единого правила.
//! 2. **Аудит ослабления.** Смена политики — событие безопасности. Переход в
//!    warn, `default = allow` или исчезновение правил обязаны оставлять след
//!    в журнале, иначе достаточно тихо отредактировать файл, чтобы контроль
//!    исчез без единой записи.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use notify::{Event, RecursiveMode, Watcher};
use zastava_core::config::{DefaultAction, PolicyMode};
use zastava_core::{CallRecord, CanonRules, Config, PolicyEngine};

use crate::logger::LogHandle;
use crate::util::{next_event_id, now_rfc3339};

/// Пауза тишины, после которой файл считается дописанным.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// То, что reload обновляет в работающем гейтвее.
#[derive(Clone)]
pub struct ReloadTargets {
    /// Движок политик.
    pub policy: Arc<RwLock<PolicyEngine>>,
    /// Правила канонизации журнала. Обновляются вместе с политикой: иначе
    /// `zastava check` показывал бы одни правила, а живой журнал писался по
    /// другим — расхождение, которое обнаружилось бы только при разборе
    /// инцидента.
    pub canon: Arc<RwLock<CanonRules>>,
    /// Журнал — для записи маркеров о смене политики.
    pub log: Option<LogHandle>,
}

/// Держатель watcher'а: Drop останавливает наблюдение и фоновый поток.
pub struct WatchGuard {
    _watcher: notify::RecommendedWatcher,
}

/// Вешает наблюдение на файл конфига. Меняется только политика и правила
/// канонизации — состав downstream-серверов фиксируется на старте
/// (плановое ограничение M1).
pub fn watch(config_path: PathBuf, targets: ReloadTargets) -> notify::Result<WatchGuard> {
    // Следим за директорией: редакторы часто пишут через rename, и watch
    // на сам файл после этого слепнет.
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let file_name = config_path.file_name().map(|n| n.to_os_string());

    let (tx, rx) = mpsc::channel::<()>();
    // Фоновый поток схлопывает серию событий в один reload. Поток завершается
    // сам, когда watcher (а с ним и отправитель) уничтожается.
    std::thread::spawn(move || {
        while rx.recv().is_ok() {
            // Ждём тишины: пока события идут, файл ещё пишется.
            loop {
                match rx.recv_timeout(DEBOUNCE) {
                    Ok(()) => continue,
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
            reload(&config_path, &targets);
        }
    });

    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let Ok(event) = result else { return };
        let ours = event
            .paths
            .iter()
            .any(|p| p.file_name().map(|n| n.to_os_string()) == file_name);
        if !ours {
            return;
        }
        let _ = tx.send(());
    })?;
    watcher.watch(&parent, RecursiveMode::NonRecursive)?;
    Ok(WatchGuard { _watcher: watcher })
}

fn reload(config_path: &Path, targets: &ReloadTargets) {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::error!(error = %e, "config unreadable on reload; keeping old policy");
            return;
        }
    };
    let config = match Config::from_toml_str(&raw) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "invalid config on reload; keeping old policy");
            return;
        }
    };

    let weakening = {
        let current = targets.policy.read().expect("policy lock poisoned");
        describe_weakening(&current, &config)
    };

    *targets.policy.write().expect("policy lock poisoned") =
        PolicyEngine::from_config(&config.policy);
    *targets.canon.write().expect("canon lock poisoned") = CanonRules::from_config(&config.canon);

    let detail = format!(
        "mode={:?}, default={:?}, rules={}",
        config.policy.mode,
        config.policy.default,
        config.policy.allow.len()
    );
    match &weakening {
        Some(reason) => tracing::warn!(reason, %detail, "policy WEAKENED on reload"),
        None => tracing::info!(%detail, "policy reloaded"),
    }
    if let Some(log) = &targets.log {
        let (event, detail) = match weakening {
            Some(reason) => ("policy_weakened", format!("{reason}; {detail}")),
            None => ("policy_reloaded", detail),
        };
        log.write(CallRecord::marker(
            now_rfc3339(),
            next_event_id(),
            event,
            Some(detail),
        ));
    }
}

/// Стало ли новое правило политики мягче старого. Отдельный маркер нужен
/// именно для ослабления: усиление контроля расследованию не мешает, а вот
/// «когда именно enforce превратился в warn» — первый вопрос по инциденту.
fn describe_weakening(current: &PolicyEngine, next: &Config) -> Option<String> {
    let mut reasons = Vec::new();
    if current.mode() == PolicyMode::Enforce && next.policy.mode == PolicyMode::Warn {
        reasons.push("enforce -> warn".to_string());
    }
    if current.default_action() == DefaultAction::Deny
        && next.policy.default == DefaultAction::Allow
    {
        reasons.push("default deny -> allow".to_string());
    }
    // Правила исчезают либо при осознанной чистке, либо при подмене файла.
    // Различить это может только человек — наше дело оставить след.
    if next.policy.allow.len() < current.rule_count() {
        reasons.push(format!(
            "rules {} -> {}",
            current.rule_count(),
            next.policy.allow.len()
        ));
    }
    // Самое M3-специфичное ослабление: правил столько же, но аргументное
    // сужение снято — удалением таблицы `args` или широким правилом ниже.
    // Счётчик правил такое не замечает, и ослабление уезжало в журнал
    // безобидным `policy_reloaded` (находка всех трёх ревью M3).
    let was = current.effective_narrowings();
    let now = PolicyEngine::from_config(&next.policy).effective_narrowings();
    let lost: Vec<&str> = was
        .iter()
        .filter(|sig| !now.contains(*sig))
        .map(String::as_str)
        .collect();
    if !lost.is_empty() {
        reasons.push(format!("narrowing lost: {}", lost.join(", ")));
    }
    (!reasons.is_empty()).then(|| reasons.join(", "))
}

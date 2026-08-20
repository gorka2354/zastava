//! MCP-обвязка Заставы: rmcp server+client, спавн downstream'ов, роутинг,
//! журнал, живой reload политик.
//!
//! stdout в режиме `run` принадлежит JSON-RPC эксклюзивно — вся диагностика
//! уходит в tracing (stderr).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod downstream;
pub mod error;
pub mod fixture;
pub mod gateway;
pub mod logger;
pub mod reload;
pub mod spawn;
pub mod util;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rmcp::ServiceExt;
use zastava_core::{Config, PolicyEngine};

use crate::error::ProxyError;

/// Опции запуска гейтвея.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Прозрачный режим: без политик и журнала (путь отступления).
    pub passthrough: bool,
    /// Путь к журналу вызовов.
    pub log_path: Option<PathBuf>,
    /// Путь к конфигу — для живого reload политик (None = reload выключен).
    pub config_path: Option<PathBuf>,
}

/// Запускает гейтвей: поднимает downstream'ы (параллельно), сервит stdio до
/// EOF клиента. Возвращается после разрыва соединения; kernel-уборщики детей
/// освобождаются на выходе.
pub async fn run(config: Config, options: RunOptions) -> Result<(), ProxyError> {
    let initialize_timeout = Duration::from_millis(config.proxy.initialize_timeout_ms);
    let call_timeout = Duration::from_millis(config.proxy.call_timeout_ms);
    let list_timeout = Duration::from_millis(config.proxy.list_timeout_ms);

    // Журнал ведётся ВСЕГДА, в том числе в passthrough: «контроль отключён»
    // и «вызовов не было» обязаны различаться при чтении журнала постфактум
    // (находка ревью M1 — иначе достаточно ZASTAVA_DISABLE=1 в чужом
    // .mcp.json, чтобы работа стала неаудируемой и это осталось незаметным).
    //
    // Заводится ДО спавна: хаб list_changed пишет в него источник каждого
    // уведомления, а сам хаб нужен уже downstream-обработчикам.
    let log = options
        .log_path
        .map(|path| logger::start(path, logger::DEFAULT_MAX_LOG_BYTES));

    // Слот заводится ДО спавна: downstream'ы получают его пустым и ждут,
    // пока подключится настоящий клиент. Иначе никак — `Peer<RoleServer>`
    // рождается только в момент `serve`, то есть заведомо позже.
    let upstream = downstream::UpstreamSlot::new();
    // Мост progress-токенов общий: его наполняет гейтвей на каждом вызове, а
    // читают обработчики всех downstream'ов.
    let progress = downstream::ProgressBridge::new();
    // Карта владельцев ресурсов общая: её наполняет гейтвей на листинге, а
    // чистит хаб list_changed, когда downstream переставил свои ресурсы.
    let resource_owners = Arc::new(RwLock::new(HashMap::new()));
    let lists =
        downstream::ListChangedHub::new(upstream.clone(), resource_owners.clone(), log.clone());

    // Eager parallel spawn (T6.4): опоздавшие/упавшие не валят остальных.
    let mut join_set = tokio::task::JoinSet::new();
    for (name, server_config) in config.servers.clone() {
        let slot = upstream.clone();
        let bridge = progress.clone();
        let hub = lists.clone();
        join_set.spawn(async move {
            let result = spawn::spawn_downstream(
                &name,
                &server_config,
                initialize_timeout,
                slot,
                bridge,
                hub,
            )
            .await;
            (name, result)
        });
    }

    let mut downstreams = HashMap::new();
    while let Some(joined) = join_set.join_next().await {
        let Ok((name, result)) = joined else { continue };
        match result {
            Ok(downstream) => {
                downstreams.insert(name, downstream.service);
            }
            Err(e) => tracing::error!(server = %name, error = %e, "downstream failed to start"),
        }
    }
    if downstreams.is_empty() {
        return Err(ProxyError::NoDownstreams);
    }

    let policy = Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy)));

    if let Some(log) = &log {
        let detail = if options.passthrough {
            Some("policy disabled: --passthrough or ZASTAVA_DISABLE=1".to_string())
        } else {
            Some(format!(
                "policy active: mode={:?}, rules={}",
                config.policy.mode,
                config.policy.allow.len()
            ))
        };
        let event = if options.passthrough {
            "policy_disabled"
        } else {
            "gateway_started"
        };
        log.write(zastava_core::CallRecord::marker(
            util::now_rfc3339(),
            util::next_event_id(),
            event,
            detail,
        ));
    }
    let canon = Arc::new(RwLock::new(zastava_core::CanonRules::from_config(
        &config.canon,
    )));
    let _watch_guard = options
        .config_path
        .filter(|_| !options.passthrough)
        .and_then(|path| {
            let targets = reload::ReloadTargets {
                policy: policy.clone(),
                canon: canon.clone(),
                log: log.clone(),
            };
            match reload::watch(path, targets) {
                Ok(guard) => Some(guard),
                Err(e) => {
                    tracing::warn!(error = %e, "config watch unavailable; live reload disabled");
                    None
                }
            }
        });

    let gateway = gateway::Gateway::with_options(
        downstreams,
        policy,
        log,
        call_timeout,
        list_timeout,
        gateway::GatewayOptions {
            passthrough: options.passthrough,
            log_args: config.log.log_args,
            canon,
            progress,
            resource_owners,
        },
    );
    let service = gateway
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| ProxyError::Serve {
            message: e.to_string(),
        })?;
    // Теперь клиент есть — отдаём его пир downstream'ам, чтобы им было куда
    // адресовать обратные запросы и уведомления.
    upstream.set(service.peer().clone());
    tracing::info!(
        passthrough = options.passthrough,
        "zastava serving on stdio"
    );
    let _ = service.waiting().await;
    tracing::info!("client disconnected; shutting down downstreams");
    Ok(())
}

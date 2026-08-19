//! Gateway: rmcp-сервер для клиента + пайплайн вызова.
//!
//! Пайплайн — явная последовательность стадий (решение T4 ревью: никакого
//! tower): разбор имени → политика → форвард с таймаутом → журнал. Стадии
//! политики и журнала — чистые функции core; здесь только склейка и IO.
//!
//! Уроки спайка (ревизия протокола 2026-07-28): paginated-результатам нужны
//! ttlMs/cacheScope, форварднутому tools/call — восстановленный resultType.
//!
//! Уроки ревью M1:
//! - `tools/list` каждого downstream идёт с таймаутом и постраничным обходом
//!   (`list_all_tools`), иначе один молчащий сервер отрубает выдачу ВСЕХ, а
//!   инструменты за первой страницей молча исчезают;
//! - форвард вызова идёт отменяемым запросом: по таймауту downstream получает
//!   `notifications/cancelled`, а запись журнала помечается `abandoned` —
//!   «мы перестали ждать», а не «вызова не было»;
//! - отказ клиенту сухой, рецепт разблокировки — человеку в stderr: подсказку
//!   читает модель, которой отказали, и это готовая инструкция обхода.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResponse, CallToolResult, ClientRequest,
    ContentBlock, ErrorData, Implementation, ListToolsResult, PaginatedRequestParams, ResultType,
    ServerCapabilities, ServerInfo, ServerResult,
};
use rmcp::service::{
    PeerRequestOptions, RequestContext, RoleClient, RoleServer, RunningService, ServiceError,
};
use rmcp::ServerHandler;
use serde_json::{Map, Value};
use zastava_core::config::NS_SEP;
use zastava_core::signature::{canonical_subset, full_args_hash, CANON_VERSION};
use zastava_core::{CallRecord, Decision, PolicyEngine, Verdict};

use crate::logger::LogHandle;
use crate::util::{next_event_id, now_rfc3339};

/// Подключённый downstream (клиентская сторона rmcp).
pub type DownstreamService = RunningService<RoleClient, ()>;

/// Итог форварда для записи в журнал.
struct CallOutcome {
    duration_ms: u64,
    result_bytes: u64,
    is_error: bool,
    /// Мы перестали ждать ответа: побочный эффект мог состояться.
    abandoned: bool,
}

impl CallOutcome {
    fn blocked() -> Self {
        Self {
            duration_ms: 0,
            result_bytes: 0,
            is_error: false,
            abandoned: false,
        }
    }
    fn failed(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            result_bytes: 0,
            is_error: true,
            abandoned: false,
        }
    }
    fn abandoned(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            result_bytes: 0,
            is_error: true,
            abandoned: true,
        }
    }
}

/// Гейтвей: реализация ServerHandler поверх множества downstream'ов.
pub struct Gateway {
    downstreams: HashMap<String, DownstreamService>,
    policy: Arc<RwLock<PolicyEngine>>,
    log: Option<LogHandle>,
    call_timeout: Duration,
    passthrough: bool,
}

impl Gateway {
    /// Собирает гейтвей. `passthrough` отключает политику (но НЕ журнал —
    /// отключённый контроль обязан оставлять след, находка ревью M1).
    pub fn new(
        downstreams: HashMap<String, DownstreamService>,
        policy: Arc<RwLock<PolicyEngine>>,
        log: Option<LogHandle>,
        call_timeout: Duration,
        passthrough: bool,
    ) -> Self {
        Self {
            downstreams,
            policy,
            log,
            call_timeout,
            passthrough,
        }
    }

    fn record(
        &self,
        server: &str,
        tool: &str,
        args: &Map<String, Value>,
        decision: Option<&Decision>,
        outcome: CallOutcome,
    ) {
        let Some(log) = &self.log else { return };
        let (decision_str, enforced, matched_rule) = match decision {
            Some(d) => (
                match d.verdict {
                    Verdict::Allow => "allow",
                    Verdict::Deny => "deny",
                },
                d.enforced,
                d.matched_rule.clone(),
            ),
            None => ("passthrough", false, None),
        };
        log.write(CallRecord {
            ts: now_rfc3339(),
            id: next_event_id(),
            server: server.to_string(),
            tool: tool.to_string(),
            canonical_subset: canonical_subset(server, tool, args),
            canon_version: CANON_VERSION,
            args_hash: full_args_hash(args),
            decision: decision_str.to_string(),
            enforced,
            matched_rule,
            duration_ms: outcome.duration_ms,
            result_bytes: outcome.result_bytes,
            is_error: outcome.is_error,
            abandoned: outcome.abandoned,
            ..Default::default()
        });
    }

    /// Отклонённый вызов тоже событие аудита: без этого перебор имён серверов
    /// и инструментов не оставляет в журнале следа (находка ревью M1).
    fn record_rejected(&self, server: &str, tool: &str, reason: &str) {
        let Some(log) = &self.log else { return };
        log.write(CallRecord {
            ts: now_rfc3339(),
            id: next_event_id(),
            server: server.to_string(),
            tool: tool.to_string(),
            decision: "rejected".to_string(),
            matched_rule: Some(reason.to_string()),
            is_error: true,
            ..Default::default()
        });
    }

    fn tool_error(message: String) -> CallToolResponse {
        // CallToolResult::error сам ставит resultType=complete и isError.
        CallToolResult::error(vec![ContentBlock::text(message)]).into()
    }
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        // Иначе клиент видит нас как "rmcp" и так же пишет в свои логи.
        info.server_info = Implementation::new("zastava", env!("CARGO_PKG_VERSION"))
            .with_title("Zastava MCP gateway");
        info.instructions = Some(
            "Zastava proxies several MCP servers behind one endpoint. Tool names are \
             prefixed with the downstream server name (`<server>__<tool>`). Calls may be \
             denied by local policy; every decision is recorded in an audit journal."
                .to_string(),
        );
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools = Vec::new();
        for (name, ds) in &self.downstreams {
            // Per-server fail-closed: молчащий или упавший downstream теряет
            // свои tools, остальные работают. Таймаут обязателен — у rmcp
            // list_tools своего нет, и один зависший сервер иначе подвешивает
            // выдачу инструментов всего гейтвея. list_all_tools обходит
            // страницы: без него инструменты за первой страницей исчезают.
            match tokio::time::timeout(self.call_timeout, ds.list_all_tools()).await {
                Ok(Ok(listed)) => {
                    for mut tool in listed {
                        tool.name = format!("{name}{NS_SEP}{}", tool.name).into();
                        tools.push(tool);
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(server = %name, error = %e, "tools/list failed; server excluded");
                }
                Err(_) => {
                    tracing::warn!(
                        server = %name,
                        timeout_ms = self.call_timeout.as_millis() as u64,
                        "tools/list timed out; server excluded from this listing"
                    );
                }
            }
        }
        // Урок спайка: 2026-07-28 требует ttlMs/cacheScope при resultType.
        Ok(ListToolsResult::with_all_items(tools)
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let full_name = request.name.to_string();
        let Some((server, tool)) = full_name.split_once(NS_SEP) else {
            self.record_rejected(&full_name, "", "tool name without namespace");
            return Err(ErrorData::invalid_params(
                format!("tool without namespace: {full_name}"),
                None,
            ));
        };
        let Some(ds) = self.downstreams.get(server) else {
            self.record_rejected(server, tool, "unknown downstream server");
            return Err(ErrorData::invalid_params(
                format!("unknown downstream: {server}"),
                None,
            ));
        };
        let args = request.arguments.clone().unwrap_or_default();

        // Стадия политики: guard не живёт через await.
        let decision = if self.passthrough {
            None
        } else {
            let engine = self.policy.read().expect("policy lock poisoned");
            Some(engine.decide(server, tool, &args))
        };

        if let Some(d) = &decision {
            if d.blocks() {
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome::blocked(),
                );
                // Рецепт разблокировки — человеку в stderr. Модели, которой
                // отказали, готовую команду обхода не выдаём.
                tracing::warn!(
                    server,
                    tool,
                    "denied by policy; to permit run: zastava allow {}{}{}",
                    server,
                    NS_SEP,
                    tool
                );
                return Ok(Self::tool_error(format!(
                    "denied by zastava policy (rule: {})",
                    d.matched_rule.as_deref().unwrap_or("default deny"),
                )));
            }
            if d.verdict == Verdict::Deny {
                tracing::warn!(
                    server,
                    tool,
                    "policy verdict deny (warn mode, call proceeds)"
                );
            }
        }

        // Стадия форварда. Отменяемый запрос с таймаутом: по истечении rmcp
        // шлёт downstream `notifications/cancelled`. Простой drop future его
        // не отменяет — downstream молча довёл бы побочный эффект до конца.
        let mut downstream_req = request;
        downstream_req.name = tool.to_string().into();
        let started = Instant::now();
        let mut options = PeerRequestOptions::no_options();
        options.timeout = Some(self.call_timeout);
        let sent = ds
            .send_cancellable_request(
                ClientRequest::CallToolRequest(CallToolRequest::new(downstream_req)),
                options,
            )
            .await;
        let outcome = match sent {
            Ok(handle) => handle.await_response().await,
            Err(e) => Err(e),
        };
        let duration_ms = started.elapsed().as_millis() as u64;

        match outcome {
            Err(ServiceError::Timeout { .. }) => {
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome::abandoned(duration_ms),
                );
                Ok(Self::tool_error(format!(
                    "downstream '{server}' did not answer within {duration_ms}ms; \
                     cancellation was sent, but the call may still have taken effect"
                )))
            }
            Err(e) => {
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome::failed(duration_ms),
                );
                Ok(Self::tool_error(format!(
                    "downstream '{server}' failed: {e}"
                )))
            }
            Ok(result) => {
                // Релеим ответ как есть, включая input_required и task:
                // решать их должен настоящий клиент, а не наш пустой хендлер.
                let response = match result {
                    ServerResult::CallToolResult(mut result) => {
                        // Урок спайка: downstream мог договориться о старой
                        // ревизии и очистить resultType — клиент требует его.
                        result.result_type = Some(ResultType::COMPLETE);
                        CallToolResponse::Complete(result)
                    }
                    ServerResult::InputRequiredResult(result) => {
                        CallToolResponse::InputRequired(result)
                    }
                    ServerResult::CreateTaskResult(result) => CallToolResponse::Task(result),
                    other => {
                        self.record(
                            server,
                            tool,
                            &args,
                            decision.as_ref(),
                            CallOutcome::failed(duration_ms),
                        );
                        return Ok(Self::tool_error(format!(
                            "downstream '{server}' returned an unexpected result: {other:?}"
                        )));
                    }
                };
                // Размер меряем по завершённому результату; промежуточные
                // ответы (input_required / task) телом не считаем.
                let (result_bytes, is_error) = match &response {
                    CallToolResponse::Complete(r) => (
                        serde_json::to_string(r)
                            .map(|s| s.len() as u64)
                            .unwrap_or(0),
                        r.is_error.unwrap_or(false),
                    ),
                    _ => (0, false),
                };
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome {
                        duration_ms,
                        result_bytes,
                        is_error,
                        abandoned: false,
                    },
                );
                Ok(response)
            }
        }
    }
}

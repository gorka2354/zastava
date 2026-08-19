//! Gateway: rmcp-сервер для клиента + пайплайн вызова.
//!
//! Пайплайн — явная последовательность стадий (решение T4 ревью: никакого
//! tower): разбор имени → политика → форвард с таймаутом → журнал. Стадии
//! политики и журнала — чистые функции core; здесь только склейка и IO.
//!
//! Уроки спайка (ревизия протокола 2026-07-28): paginated-результатам нужны
//! ttlMs/cacheScope, форварднутому tools/call — восстановленный resultType.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData,
    ListToolsResult, PaginatedRequestParams, ResultType, ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
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
}

impl CallOutcome {
    fn blocked() -> Self {
        Self {
            duration_ms: 0,
            result_bytes: 0,
            is_error: false,
        }
    }
    fn failed(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            result_bytes: 0,
            is_error: true,
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
    /// Собирает гейтвей. `passthrough` отключает политику и журнал —
    /// путь отступления (T6.6 ревью).
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
            None => ("allow", false, None),
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
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools = Vec::new();
        for (name, ds) in &self.downstreams {
            // Per-server fail-closed: умерший downstream теряет свои tools,
            // остальные продолжают работать (решение T6.12 плана).
            match ds.list_tools(Default::default()).await {
                Ok(listed) => {
                    for mut tool in listed.tools {
                        tool.name = format!("{name}{NS_SEP}{}", tool.name).into();
                        tools.push(tool);
                    }
                }
                Err(e) => {
                    tracing::warn!(server = %name, error = %e, "tools/list failed; server excluded");
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
            return Err(ErrorData::invalid_params(
                format!("tool without namespace: {full_name}"),
                None,
            ));
        };
        let Some(ds) = self.downstreams.get(server) else {
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
                tracing::info!(server, tool, "denied by policy");
                return Ok(Self::tool_error(format!(
                    "denied by zastava (rule: {}): run `zastava allow {server}{NS_SEP}{tool}` to permit",
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

        // Стадия форварда: зависший downstream не вешает гейтвей (2A).
        let mut downstream_req = request;
        downstream_req.name = tool.to_string().into();
        let started = Instant::now();
        let outcome = tokio::time::timeout(self.call_timeout, ds.call_tool(downstream_req)).await;
        let duration_ms = started.elapsed().as_millis() as u64;

        match outcome {
            Err(_elapsed) => {
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome::failed(duration_ms),
                );
                Ok(Self::tool_error(format!(
                    "downstream '{server}' timed out after {duration_ms}ms"
                )))
            }
            Ok(Err(e)) => {
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
            Ok(Ok(mut result)) => {
                // Урок спайка: downstream мог договориться о старой ревизии и
                // очистить resultType — клиент на 2026-07-28 требует его.
                result.result_type = Some(ResultType::COMPLETE);
                let result_bytes = serde_json::to_string(&result)
                    .map(|s| s.len() as u64)
                    .unwrap_or(0);
                let is_error = result.is_error.unwrap_or(false);
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome {
                        duration_ms,
                        result_bytes,
                        is_error,
                    },
                );
                Ok(result.into())
            }
        }
    }
}

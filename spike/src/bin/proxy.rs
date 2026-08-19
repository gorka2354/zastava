//! Спайк-прокси: ядро гипотезы Заставы в минимальной форме.
//!
//! Server-role (для Claude Code, stdio) + client-role (к двум спавнутым
//! echo-server'ам) В ОДНОМ ПРОЦЕССЕ — главный технический риск проекта.
//! Tools downstream'ов неймспейсятся как `<server>__<tool>`.
//!
//! stdout принадлежит JSON-RPC; диагностика — только в stderr.

use std::collections::HashMap;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleClient, RoleServer, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::{ServerHandler, ServiceExt};
use tokio::process::Command;

type Downstream = RunningService<RoleClient, ()>;

struct Proxy {
    downstreams: Arc<HashMap<String, Downstream>>,
}

impl ServerHandler for Proxy {
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
        for (name, ds) in self.downstreams.iter() {
            let listed = ds
                .list_tools(Default::default())
                .await
                .map_err(|e| ErrorData::internal_error(format!("downstream {name}: {e}"), None))?;
            for mut tool in listed.tools {
                tool.name = format!("{name}__{}", tool.name).into();
                tools.push(tool);
            }
        }
        // Протокол 2026-07-28 требует ttlMs/cacheScope при наличии resultType:
        // отдаём некэшируемый приватный результат.
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
        let (server, tool) = full_name.split_once("__").ok_or_else(|| {
            ErrorData::invalid_params(format!("tool without namespace: {full_name}"), None)
        })?;
        let ds = self.downstreams.get(server).ok_or_else(|| {
            ErrorData::invalid_params(format!("unknown downstream: {server}"), None)
        })?;
        eprintln!("[proxy] forwarding {full_name}");
        let mut downstream_req = request;
        downstream_req.name = tool.to_string().into();
        let mut result = ds
            .call_tool(downstream_req)
            .await
            .map_err(|e| ErrorData::internal_error(format!("forward failed: {e}"), None))?;
        // Downstream мог договориться о старой версии протокола и очистить
        // resultType; клиент на 2026-07-28 требует его — восстанавливаем.
        result.result_type = Some(rmcp::model::ResultType::COMPLETE);
        Ok(result.into())
    }
}

async fn spawn_downstream(name: &str) -> anyhow::Result<Downstream> {
    let exe = std::env::current_exe()?;
    let sibling = exe.with_file_name(if cfg!(windows) {
        "echo-server.exe"
    } else {
        "echo-server"
    });
    let mut cmd = Command::new(sibling);
    cmd.env("SPIKE_NAME", name);
    let transport = TokioChildProcess::new(cmd)?;
    let service = ().serve(transport).await?;
    eprintln!("[proxy] downstream '{name}' up");
    Ok(service)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("[proxy] starting: spawning 2 downstreams");
    let mut downstreams = HashMap::new();
    downstreams.insert("alpha".to_string(), spawn_downstream("alpha").await?);
    downstreams.insert("beta".to_string(), spawn_downstream("beta").await?);

    let proxy = Proxy {
        downstreams: Arc::new(downstreams),
    };
    let service = proxy.serve(rmcp::transport::stdio()).await?;
    eprintln!("[proxy] serving on stdio");
    service.waiting().await?;
    Ok(())
}

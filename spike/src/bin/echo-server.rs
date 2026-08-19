//! Фиктивный downstream MCP-сервер для спайка.
//! Имя берётся из env SPIKE_NAME (alpha/beta) — им сервер подписывает ответы.
//! stdout принадлежит JSON-RPC; вся диагностика — только в stderr.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};
use rmcp::transport::stdio;

#[derive(Clone)]
struct EchoServer {
    name: String,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct PingParams {
    /// Сообщение, которое сервер вернёт обратно
    message: String,
}

#[tool_router]
impl EchoServer {
    fn new(name: String) -> Self {
        Self {
            name,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Echo back a message with the server's name")]
    async fn ping(&self, Parameters(PingParams { message }): Parameters<PingParams>) -> String {
        format!("[{}] pong: {}", self.name, message)
    }
}

#[tool_handler]
impl ServerHandler for EchoServer {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let name = std::env::var("SPIKE_NAME").unwrap_or_else(|_| "alpha".to_string());
    eprintln!("[echo-server:{name}] starting");
    let service = EchoServer::new(name).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

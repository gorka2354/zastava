//! Тестовая фикстура: минимальный echo MCP-сервер.
//!
//! Используется интеграционными тестами proxy (in-process через duplex) и
//! e2e-тестами cli (как реальный дочерний процесс, бин `zastava-test-echo`).
//! Управление через env:
//! - `ECHO_FIXTURE_NAME` — имя, которым сервер подписывает ответы;
//! - `ECHO_FIXTURE_PID_FILE` — куда записать свой pid (для EOF-теста);
//! - `slow_ping` спит указанное число мс — для теста таймаута.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};

/// Echo-сервер фикстуры.
#[derive(Clone)]
pub struct EchoFixture {
    name: String,
    /// Читается макросом #[tool_handler] в impl ServerHandler; для rustc
    /// поле выглядит мёртвым.
    #[allow(dead_code)]
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct PingParams {
    /// Сообщение для эха.
    message: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct SlowParams {
    /// Сколько миллисекунд спать перед ответом.
    ms: u64,
}

#[tool_router]
impl EchoFixture {
    /// Создаёт фикстуру с именем.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Echo back a message")]
    async fn ping(&self, Parameters(PingParams { message }): Parameters<PingParams>) -> String {
        format!("[{}] pong: {message}", self.name)
    }

    #[tool(description = "Echo after sleeping for ms milliseconds")]
    async fn slow_ping(&self, Parameters(SlowParams { ms }): Parameters<SlowParams>) -> String {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        format!("[{}] slow pong after {ms}ms", self.name)
    }
}

#[tool_handler]
impl ServerHandler for EchoFixture {}

/// Точка входа бинаря фикстуры: stdio-сервер до EOF клиента.
pub async fn run_echo_fixture_stdio() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let name = std::env::var("ECHO_FIXTURE_NAME").unwrap_or_else(|_| "echo".to_string());
    if let Ok(pid_file) = std::env::var("ECHO_FIXTURE_PID_FILE") {
        let _ = std::fs::write(pid_file, std::process::id().to_string());
    }
    let service = EchoFixture::new(name)
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}

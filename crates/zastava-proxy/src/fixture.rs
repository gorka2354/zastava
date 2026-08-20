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

/// Аргументы `write_file`: путь-идентификатор ресурса плюс содержимое,
/// которое в журнал попадать НЕ должно.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WriteParams {
    /// Куда пишем.
    path: String,
    /// Что пишем.
    content: String,
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

    #[tool(description = "Pretend to write a file at path")]
    async fn write_file(
        &self,
        Parameters(WriteParams { path, content }): Parameters<WriteParams>,
    ) -> String {
        format!("[{}] wrote {} bytes to {path}", self.name, content.len())
    }

    #[tool(description = "Ask the connected client for its root directories")]
    #[allow(deprecated)] // roots устарели по SEP-2577; фикстуре они нужны как проба
    async fn ask_roots(&self, peer: rmcp::Peer<rmcp::service::RoleServer>) -> String {
        // Инструмент существует ради проверки ОБРАТНОГО направления: сервер
        // спрашивает своего клиента (то есть заставу). До M2-full застава
        // отвечала выдуманным `Ok(пустой список)` от имени пользователя.
        match peer.list_roots().await {
            Ok(result) => format!("ok: {} roots", result.roots.len()),
            Err(e) => format!("err: {e}"),
        }
    }

    #[tool(description = "Echo after sleeping for ms milliseconds")]
    async fn slow_ping(&self, Parameters(SlowParams { ms }): Parameters<SlowParams>) -> String {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        format!("[{}] slow pong after {ms}ms", self.name)
    }
}

#[tool_handler]
impl ServerHandler for EchoFixture {}

/// Фикстура, зависающая на `tools/list`: моделирует downstream, который
/// прошёл initialize, а потом замолчал (ждёт сеть, OAuth, песочницу).
#[derive(Clone)]
pub struct HangingFixture;

impl rmcp::ServerHandler for HangingFixture {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::model::ErrorData> {
        std::future::pending::<()>().await;
        unreachable!("pending future never resolves")
    }
}

/// Фикстура с ДВУМЯ страницами инструментов: проверяет, что гейтвей
/// действительно обходит пагинацию, а не берёт первую страницу.
#[derive(Clone)]
pub struct PagedFixture;

fn stub_tool(name: &str) -> rmcp::model::Tool {
    rmcp::model::Tool::new(
        name.to_string(),
        "stub".to_string(),
        std::sync::Arc::new(serde_json::Map::new()),
    )
}

impl rmcp::ServerHandler for PagedFixture {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        info
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::model::ErrorData> {
        let cursor = request.and_then(|r| r.cursor);
        let result = match cursor.as_deref() {
            None => {
                let mut r = rmcp::model::ListToolsResult::with_all_items(vec![stub_tool("page1")]);
                r.next_cursor = Some("page2".to_string());
                r
            }
            Some(_) => rmcp::model::ListToolsResult::with_all_items(vec![stub_tool("page2")]),
        };
        Ok(result
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }
}

/// Фикстура, бесконечно повторяющая один и тот же курсор: без ограничения
/// числа страниц гейтвей крутил бы её до OOM (находка верификации M1).
#[derive(Clone)]
pub struct EndlessPagingFixture;

impl rmcp::ServerHandler for EndlessPagingFixture {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::model::ErrorData> {
        let mut result = rmcp::model::ListToolsResult::with_all_items(vec![stub_tool("endless")]);
        result.next_cursor = Some("same-cursor".to_string());
        Ok(result
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }
}

/// Фикстура с ресурсом и промптом: настоящие MCP-серверы отдают не только
/// инструменты, и M2-lite обязан их проксировать.
#[derive(Clone)]
pub struct RichFixture;

impl rmcp::ServerHandler for RichFixture {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .enable_prompts()
            .build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::model::ErrorData> {
        Ok(
            rmcp::model::ListToolsResult::with_all_items(vec![stub_tool("noop")])
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::model::ErrorData> {
        let note = rmcp::model::Resource::new("mem://note", "note");
        // Ресурс, который значится в списке, но при чтении отвечает ошибкой
        // с КОНКРЕТНЫМ кодом. Нужен, чтобы проверить: гейтвей переносит код
        // наверх, а не схлопывает всё в internal_error.
        let broken = rmcp::model::Resource::new("mem://broken", "broken");
        Ok(
            rmcp::model::ListResourcesResult::with_all_items(vec![note, broken])
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private),
        )
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::model::ErrorData> {
        if request.uri == "mem://broken" {
            // Осмысленный код, а не «внутренняя ошибка»: клиент должен уметь
            // отличить «ресурса нет» от «сломался посредник».
            return Err(rmcp::model::ErrorData::resource_not_found(
                "note was deleted",
                None,
            ));
        }
        if request.uri != "mem://note" {
            return Err(rmcp::model::ErrorData::invalid_params("unknown uri", None));
        }
        let contents = rmcp::model::ResourceContents::text("resource payload", "mem://note");
        let mut result = rmcp::model::ReadResourceResult::new(vec![contents]);
        // Имитируем downstream старой ревизии протокола: гейтвей обязан
        // восстановить resultType, иначе современный клиент отвергнет ответ.
        result.result_type = None;
        Ok(rmcp::model::ReadResourceResponse::Complete(result))
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, rmcp::model::ErrorData> {
        let prompt = rmcp::model::Prompt::new("greet", Some("greeting prompt"), None);
        Ok(rmcp::model::ListPromptsResult::with_all_items(vec![prompt])
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::GetPromptResponse, rmcp::model::ErrorData> {
        if request.name != "greet" {
            return Err(rmcp::model::ErrorData::invalid_params(
                "unknown prompt",
                None,
            ));
        }
        let mut result =
            rmcp::model::GetPromptResult::new(vec![rmcp::model::PromptMessage::new_text(
                rmcp::model::Role::User,
                "hello from fixture",
            )]);
        result.result_type = None;
        Ok(rmcp::model::GetPromptResponse::Complete(result))
    }
}

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

/// Фикстура, репортящая ход длинной операции.
///
/// Нужна для проверки перевода progress-токенов: downstream шлёт уведомления
/// на СВОЙ токен (его назначил rmcp, когда застава отправляла запрос вниз), а
/// клиент ждёт свой. Без перевода прогресс либо теряется, либо адресуется в
/// пустоту.
#[derive(Clone)]
pub struct ProgressFixture;

impl rmcp::ServerHandler for ProgressFixture {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::model::ErrorData> {
        Ok(
            rmcp::model::ListToolsResult::with_all_items(vec![stub_tool("work")])
                .with_ttl_ms(0)
                .with_cache_scope(rmcp::model::CacheScope::Private),
        )
    }

    async fn call_tool(
        &self,
        _request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::model::ErrorData> {
        if let Some(token) = context.meta.get_progress_token() {
            for step in 1..=3u32 {
                let param = rmcp::model::ProgressNotificationParam::new(token.clone(), step as f64)
                    .with_total(3.0)
                    .with_message(format!("step {step}"));
                let _ = context.peer.notify_progress(param).await;
            }
        }
        // Свой токен фикстура НАЗЫВАЕТ в ответе: тест обязан убедиться, что
        // он отличается от клиентского, иначе проверка перевода вырождается
        // в тавтологию (счётчики токенов у разных пиров начинаются с нуля и
        // легко совпадают).
        let token_note = match context.meta.get_progress_token() {
            Some(t) => format!("done token={t:?}"),
            None => "done token=none".to_string(),
        };
        let mut result =
            rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(token_note)]);
        result.result_type = Some(rmcp::model::ResultType::COMPLETE);
        Ok(rmcp::model::CallToolResponse::Complete(result))
    }
}

//! Тестовая фикстура для e2e-тестов: echo MCP-сервер как реальный процесс.
//! Не предназначен для использования вне тестов (см. zastava_proxy::fixture).

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    if let Err(e) = zastava_proxy::fixture::run_echo_fixture_stdio().await {
        eprintln!("[zastava-test-echo] error: {e}");
        std::process::exit(1);
    }
}

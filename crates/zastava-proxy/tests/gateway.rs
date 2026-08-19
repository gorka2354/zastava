//! Интеграционные тесты гейтвея: клиент ↔ Gateway ↔ downstream, всё
//! in-process через duplex-транспорт (спавн реальных процессов покрывают
//! e2e-тесты zastava-cli).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::ServiceExt;
use zastava_core::{Config, PolicyEngine};
use zastava_proxy::fixture::{EchoFixture, EndlessPagingFixture, HangingFixture};
use zastava_proxy::gateway::{DownstreamService, Gateway};
use zastava_proxy::logger;

/// Поднимает in-process фикстуру и возвращает клиентский сервис к ней.
async fn fixture_downstream(name: &str) -> DownstreamService {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let fixture = EchoFixture::new(name);
    tokio::spawn(async move {
        if let Ok(running) = fixture.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.expect("fixture client")
}

struct TestGateway {
    client: rmcp::service::RunningService<rmcp::service::RoleClient, ()>,
    log_path: std::path::PathBuf,
    _log_dir: tempfile::TempDir,
}

/// Собирает гейтвей с одной фикстурой `alpha` и заданной политикой.
async fn gateway_with(policy_toml: &str, call_timeout_ms: u64, passthrough: bool) -> TestGateway {
    let config = Config::from_toml_str(policy_toml).expect("test config");
    let mut downstreams = HashMap::new();
    downstreams.insert("alpha".to_string(), fixture_downstream("alpha").await);

    let log_dir = tempfile::tempdir().expect("tempdir");
    let log_path = log_dir.path().join("calls.jsonl");
    let log = logger::start(log_path.clone(), logger::DEFAULT_MAX_LOG_BYTES);

    let gateway = Gateway::new(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        Some(log),
        Duration::from_millis(call_timeout_ms),
        Duration::from_millis(2_000),
        passthrough,
    );

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = gateway.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("gateway client");
    TestGateway {
        client,
        log_path,
        _log_dir: log_dir,
    }
}

fn call(name: &str, args: serde_json::Value) -> CallToolRequestParams {
    let mut request = CallToolRequestParams::default();
    request.name = name.to_string().into();
    request.arguments = match args {
        serde_json::Value::Object(map) => Some(map),
        _ => None,
    };
    request
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn wait_records(path: &std::path::Path, at_least: usize) -> Vec<zastava_core::CallRecord> {
    for _ in 0..100 {
        if let Ok(records) = logger::read_records(path) {
            if records.len() >= at_least {
                return records;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    logger::read_records(path).unwrap_or_default()
}

const ENFORCE_NO_RULES: &str = r#"
[servers.alpha]
command = "unused-in-tests"
[policy]
mode = "enforce"
default = "deny"
"#;

const ENFORCE_ALLOW_ALL: &str = r#"
[servers.alpha]
command = "unused-in-tests"
[policy]
mode = "enforce"
[[policy.allow]]
sig = "alpha__*"
"#;

const WARN_NO_RULES: &str = r#"
[servers.alpha]
command = "unused-in-tests"
"#;

#[tokio::test]
async fn lists_namespaced_tools() {
    let gw = gateway_with(WARN_NO_RULES, 5_000, false).await;
    let listed = gw.client.list_tools(Default::default()).await.unwrap();
    let names: Vec<String> = listed.tools.iter().map(|t| t.name.to_string()).collect();
    assert!(names.contains(&"alpha__ping".to_string()), "{names:?}");
    assert!(names.contains(&"alpha__slow_ping".to_string()), "{names:?}");
}

#[tokio::test]
async fn enforce_denies_uncovered_call_and_logs_it() {
    let gw = gateway_with(ENFORCE_NO_RULES, 5_000, false).await;
    let result = gw
        .client
        .call_tool(call("alpha__ping", serde_json::json!({"message": "hi"})))
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    let text = text_of(&result);
    assert!(text.contains("denied by zastava policy"), "{text}");
    assert!(
        !text.contains("zastava allow"),
        "рецепт обхода не должен уезжать в контекст модели: {text}"
    );

    let records = wait_records(&gw.log_path, 1).await;
    assert_eq!(records[0].decision, "deny");
    assert!(records[0].enforced);
    assert_eq!(
        records[0].duration_ms, 0,
        "заблокированный вызов не ходил вниз"
    );
}

#[tokio::test]
async fn warn_mode_forwards_but_logs_deny_verdict() {
    let gw = gateway_with(WARN_NO_RULES, 5_000, false).await;
    let result = gw
        .client
        .call_tool(call("alpha__ping", serde_json::json!({"message": "hi"})))
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true));
    assert!(text_of(&result).contains("[alpha] pong: hi"));

    let records = wait_records(&gw.log_path, 1).await;
    assert_eq!(records[0].decision, "deny", "вердикт остаётся deny");
    assert!(!records[0].enforced, "но warn не блокирует");
}

#[tokio::test]
async fn allowed_call_forwards_and_logs_rule() {
    let gw = gateway_with(ENFORCE_ALLOW_ALL, 5_000, false).await;
    let result = gw
        .client
        .call_tool(call("alpha__ping", serde_json::json!({"message": "ok"})))
        .await
        .unwrap();
    assert!(text_of(&result).contains("[alpha] pong: ok"));

    let records = wait_records(&gw.log_path, 1).await;
    assert_eq!(records[0].decision, "allow");
    assert_eq!(records[0].matched_rule.as_deref(), Some("alpha__*"));
    assert!(records[0].result_bytes > 0);
}

#[tokio::test]
async fn hung_downstream_times_out_without_hanging_gateway() {
    let gw = gateway_with(ENFORCE_ALLOW_ALL, 300, false).await;
    let result = gw
        .client
        .call_tool(call("alpha__slow_ping", serde_json::json!({"ms": 60_000})))
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(true));
    let text = text_of(&result);
    assert!(text.contains("stopped waiting"), "{text}");
    assert!(
        text.contains("may still have taken effect"),
        "сообщение обязано честно говорить, что побочный эффект мог случиться: {text}"
    );

    // Гейтвей жив: следующий быстрый вызов проходит.
    let alive = gw
        .client
        .call_tool(call(
            "alpha__ping",
            serde_json::json!({"message": "still here"}),
        ))
        .await
        .unwrap();
    assert!(text_of(&alive).contains("still here"));

    let records = wait_records(&gw.log_path, 2).await;
    assert!(records[0].is_error, "таймаут записан как ошибка");
    assert!(
        records[0].abandoned,
        "запись обязана быть помечена abandoned: вызов мог состояться"
    );
}

#[tokio::test]
async fn passthrough_skips_policy() {
    let gw = gateway_with(ENFORCE_NO_RULES, 5_000, true).await;
    let result = gw
        .client
        .call_tool(call("alpha__ping", serde_json::json!({"message": "free"})))
        .await
        .unwrap();
    assert!(
        text_of(&result).contains("[alpha] pong: free"),
        "passthrough обязан игнорировать enforce-deny"
    );
}

#[tokio::test]
async fn call_without_namespace_is_protocol_error() {
    let gw = gateway_with(WARN_NO_RULES, 5_000, false).await;
    let err = gw
        .client
        .call_tool(call("ping", serde_json::json!({})))
        .await
        .expect_err("без неймспейса — протокольная ошибка");
    assert!(err.to_string().contains("namespace"), "{err}");
}

/// Поднимает произвольную серверную фикстуру и возвращает клиент к ней.
async fn serve_fixture<S>(fixture: S) -> DownstreamService
where
    S: rmcp::ServerHandler + Send + Sync + 'static,
{
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = fixture.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.expect("fixture client")
}

/// Собирает гейтвей поверх готового набора downstream'ов.
async fn gateway_over(
    downstreams: HashMap<String, DownstreamService>,
    list_timeout_ms: u64,
) -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    let config = Config::from_toml_str(WARN_NO_RULES).unwrap();
    let gateway = Gateway::new(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        None,
        Duration::from_millis(5_000),
        Duration::from_millis(list_timeout_ms),
        false,
    );
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = gateway.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.unwrap()
}

/// Инструменты за первой страницей раньше исчезали молча (P1 ревью M1).
#[tokio::test]
async fn paginated_downstream_yields_all_pages() {
    let mut downstreams = HashMap::new();
    downstreams.insert(
        "paged".to_string(),
        serve_fixture(zastava_proxy::fixture::PagedFixture).await,
    );
    let client = gateway_over(downstreams, 2_000).await;
    let listed = client.list_tools(Default::default()).await.unwrap();
    let names: Vec<String> = listed.tools.iter().map(|t| t.name.to_string()).collect();
    assert!(names.contains(&"paged__page1".to_string()), "{names:?}");
    assert!(
        names.contains(&"paged__page2".to_string()),
        "инструмент со ВТОРОЙ страницы обязан доехать: {names:?}"
    );
}

/// Downstream, вечно повторяющий курсор, раньше крутил бы обход до OOM:
/// таймаут ограничивал время, но не память (P1 верификации фиксов M1).
#[tokio::test]
async fn endless_pagination_is_bounded() {
    let mut downstreams = HashMap::new();
    downstreams.insert(
        "endless".to_string(),
        serve_fixture(EndlessPagingFixture).await,
    );
    let client = gateway_over(downstreams, 30_000).await;
    let listed = tokio::time::timeout(
        Duration::from_secs(20),
        client.list_tools(Default::default()),
    )
    .await
    .expect("обход обязан оборваться сам, не по таймауту теста")
    .expect("list_tools");
    assert!(
        listed.tools.len() <= 2,
        "повтор курсора обязан обрывать пагинацию сразу: {}",
        listed.tools.len()
    );
}

#[tokio::test]
async fn hung_downstream_does_not_block_tool_listing_of_others() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = HangingFixture.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let hung = ().serve(client_io).await.expect("hung client");

    let mut downstreams = HashMap::new();
    downstreams.insert("alpha".to_string(), fixture_downstream("alpha").await);
    downstreams.insert("hung".to_string(), hung);

    let config = Config::from_toml_str(WARN_NO_RULES).unwrap();
    let gateway = Gateway::new(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        None,
        Duration::from_millis(300),
        Duration::from_millis(300),
        false,
    );
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = gateway.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.unwrap();

    let listed = tokio::time::timeout(
        Duration::from_secs(5),
        client.list_tools(Default::default()),
    )
    .await
    .expect("выдача инструментов не должна висеть из-за одного downstream")
    .expect("list_tools");
    let names: Vec<String> = listed.tools.iter().map(|t| t.name.to_string()).collect();
    assert!(
        names.iter().any(|n| n == "alpha__ping"),
        "инструменты живого сервера обязаны доехать: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("hung__")),
        "молчащий сервер исключается из выдачи: {names:?}"
    );
}

/// Отклонённые вызовы (неизвестный сервер, имя без неймспейса) — тоже
/// события аудита: без записи перебор имён невидим в журнале.
#[tokio::test]
async fn rejected_calls_are_recorded() {
    let gw = gateway_with(WARN_NO_RULES, 5_000, false).await;
    let _ = gw
        .client
        .call_tool(call("ghost__tool", serde_json::json!({})))
        .await;
    let _ = gw
        .client
        .call_tool(call("noseparator", serde_json::json!({})))
        .await;

    let records = wait_records(&gw.log_path, 2).await;
    assert_eq!(records.len(), 2, "оба отказа должны быть в журнале");
    assert!(records.iter().all(|r| r.decision == "rejected"));
}

#[tokio::test]
async fn policy_reload_picks_up_new_rules_without_restart() {
    // Стартуем с enforce deny, затем правим конфиг на диске — файловый
    // watcher должен подхватить allow-правило без пересоздания гейтвея.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("zastava.toml");
    std::fs::write(&config_path, ENFORCE_NO_RULES).unwrap();
    let config = Config::from_toml_str(ENFORCE_NO_RULES).unwrap();

    let policy = Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy)));
    let _watch = zastava_proxy::reload::watch(config_path.clone(), policy.clone()).unwrap();

    let mut downstreams = HashMap::new();
    downstreams.insert("alpha".to_string(), fixture_downstream("alpha").await);
    let gateway = Gateway::new(
        downstreams,
        policy,
        None,
        Duration::from_millis(5_000),
        Duration::from_millis(2_000),
        false,
    );
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = gateway.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.unwrap();

    let denied = client
        .call_tool(call("alpha__ping", serde_json::json!({"message": "x"})))
        .await
        .unwrap();
    assert_eq!(denied.is_error, Some(true), "до reload — deny");

    std::fs::write(&config_path, ENFORCE_ALLOW_ALL).unwrap();

    // Файловые события асинхронны: ждём подхвата с потолком.
    let mut passed = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let result = client
            .call_tool(call("alpha__ping", serde_json::json!({"message": "after"})))
            .await
            .unwrap();
        if result.is_error != Some(true) {
            passed = true;
            break;
        }
    }
    assert!(passed, "reload не подхватил allow-правило за 5с");
}

//! Интеграционные тесты гейтвея: клиент ↔ Gateway ↔ downstream, всё
//! in-process через duplex-транспорт (спавн реальных процессов покрывают
//! e2e-тесты zastava-cli).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::ServiceExt;
use zastava_core::{Config, PolicyEngine};
use zastava_proxy::downstream::{DownstreamHandler, UpstreamSlot};
use zastava_proxy::fixture::{
    EchoFixture, EndlessPagingFixture, HangingFixture, ProgressFixture, RichFixture,
};
use zastava_proxy::gateway::{DownstreamService, Gateway, GatewayOptions};
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
    // Клиент-роль теперь настоящий обработчик, а не юнит-тип: тесты
    // обязаны ходить тем же путём, что и боевой код.
    DownstreamHandler::new("test", UpstreamSlot::new())
        .serve(client_io)
        .await
        .expect("fixture client")
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

/// Как `gateway_with`, но с включённой канонизацией аргументов (M3).
async fn gateway_with_canon(config_toml: &str) -> TestGateway {
    let config = Config::from_toml_str(config_toml).expect("test config");
    let mut downstreams = HashMap::new();
    downstreams.insert("alpha".to_string(), fixture_downstream("alpha").await);

    let log_dir = tempfile::tempdir().expect("tempdir");
    let log_path = log_dir.path().join("calls.jsonl");
    let log = logger::start(log_path.clone(), logger::DEFAULT_MAX_LOG_BYTES);

    let gateway = Gateway::with_options(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        Some(log),
        Duration::from_millis(5_000),
        Duration::from_millis(2_000),
        GatewayOptions {
            canon: Arc::new(RwLock::new(zastava_core::CanonRules::from_config(
                &config.canon,
            ))),
            ..GatewayOptions::default()
        },
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
    // Клиент-роль теперь настоящий обработчик, а не юнит-тип: тесты
    // обязаны ходить тем же путём, что и боевой код.
    DownstreamHandler::new("test", UpstreamSlot::new())
        .serve(client_io)
        .await
        .expect("fixture client")
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

/// Клиент, договаривающийся о ревизии 2026-07-28. Дефолтный клиент rmcp
/// объявляет 2025-11-25, и rmcp сам вычищает `resultType` для таких пиров —
/// то есть на дефолтном клиенте баг «forwarded result без resultType»
/// невоспроизводим. Живой Claude Code договаривается именно о 2026-07-28.
#[derive(Clone)]
struct ModernClient;

impl rmcp::ClientHandler for ModernClient {
    fn get_info(&self) -> rmcp::model::ClientInfo {
        let mut info = rmcp::model::ClientInfo::default();
        info.protocol_version = rmcp::model::ProtocolVersion::V_2026_07_28;
        info
    }
}

/// M2-lite: настоящие MCP-серверы отдают не только инструменты. Ресурс
/// маршрутизируется по URI (префиксовать URI нельзя — он адрес), промпт — по
/// префиксу имени, как инструмент.
#[tokio::test]
async fn resources_and_prompts_are_proxied() {
    let mut downstreams = HashMap::new();
    downstreams.insert("rich".to_string(), serve_fixture(RichFixture).await);
    let config = Config::from_toml_str(WARN_NO_RULES).unwrap();
    let gateway = Gateway::new(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
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
    let client = ModernClient.serve(client_io).await.unwrap();

    // Возможности вычисляются из downstream'ов, а не объявляются вслепую.
    let info = client.peer_info().expect("server info");
    assert!(info.capabilities.resources.is_some(), "ресурсы объявлены");
    assert!(info.capabilities.prompts.is_some(), "промпты объявлены");

    let resources = client.list_resources(Default::default()).await.unwrap();
    let uris: Vec<String> = resources.resources.iter().map(|r| r.uri.clone()).collect();
    assert_eq!(
        uris,
        vec!["mem://note", "mem://broken"],
        "URI остаётся немодифицированным"
    );

    let read = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new("mem://note"))
        .await
        .expect("resource read");
    let payload = format!("{read:?}");
    assert!(payload.contains("resource payload"), "{payload}");
    // Урок спайка распространяется и на ресурсы: downstream старой ревизии
    // отдаёт результат без resultType, клиент 2026-07-28 такой отвергает.
    assert!(
        read.result_type.is_some(),
        "гейтвей обязан восстановить resultType"
    );

    let prompts = client.list_prompts(Default::default()).await.unwrap();
    let names: Vec<String> = prompts.prompts.iter().map(|p| p.name.clone()).collect();
    assert_eq!(names, vec!["rich__greet"], "имя промпта префиксуется");

    let got = client
        .get_prompt(rmcp::model::GetPromptRequestParams::new("rich__greet"))
        .await
        .expect("prompt get");
    assert!(format!("{got:?}").contains("hello from fixture"));
    assert!(
        got.result_type.is_some(),
        "resultType обязан быть восстановлен и для промптов"
    );
}

/// Ресурсы и промпты — тоже действия агента и обязаны попадать в аудит.
#[tokio::test]
async fn resource_and_prompt_access_is_audited() {
    let log_dir = tempfile::tempdir().unwrap();
    let log_path = log_dir.path().join("calls.jsonl");
    let log = logger::start(log_path.clone(), logger::DEFAULT_MAX_LOG_BYTES);

    let mut downstreams = HashMap::new();
    downstreams.insert("rich".to_string(), serve_fixture(RichFixture).await);
    let config = Config::from_toml_str(WARN_NO_RULES).unwrap();
    let gateway = Gateway::new(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        Some(log),
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

    let _ = client.list_resources(Default::default()).await.unwrap();
    let _ = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new("mem://note"))
        .await
        .unwrap();
    let _ = client
        .get_prompt(rmcp::model::GetPromptRequestParams::new("rich__greet"))
        .await
        .unwrap();

    let records = wait_records(&log_path, 2).await;
    let tools: Vec<String> = records.iter().map(|r| r.tool.clone()).collect();
    assert!(
        tools.iter().any(|t| t == "zastava.resource"),
        "чтение ресурса в журнале: {tools:?}"
    );
    assert!(
        tools.iter().any(|t| t.starts_with("zastava.prompt.")),
        "получение промпта в журнале: {tools:?}"
    );
}

/// Сервер без ресурсов не должен заставлять гейтвей обещать их клиенту.
#[tokio::test]
async fn capabilities_reflect_actual_downstreams() {
    let mut downstreams = HashMap::new();
    downstreams.insert("alpha".to_string(), fixture_downstream("alpha").await);
    let client = gateway_over(downstreams, 2_000).await;
    let info = client.peer_info().expect("server info");
    assert!(info.capabilities.tools.is_some());
    assert!(
        info.capabilities.resources.is_none(),
        "ресурсов ни у кого нет — обещать их нельзя"
    );
}

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
    let hung = DownstreamHandler::new("hung", UpstreamSlot::new())
        .serve(client_io)
        .await
        .expect("hung client");

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
    let _watch = zastava_proxy::reload::watch(
        config_path.clone(),
        zastava_proxy::reload::ReloadTargets {
            policy: policy.clone(),
            canon: Arc::new(RwLock::new(zastava_core::CanonRules::default())),
            log: None,
        },
    )
    .unwrap();

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

const ENFORCE_PATH_PREFIX: &str = r#"
[servers.alpha]
command = "unused-in-tests"
[policy]
mode = "enforce"
default = "deny"
[[policy.allow]]
sig = "alpha__write_file"
args = { path = { prefix = "C:/work/zastava" } }
"#;

#[tokio::test]
async fn argument_rule_narrows_a_tool_through_the_proxy() {
    // Ради этого проект и существует: клиентский permissions.allow умеет
    // только «инструмент можно или нельзя», а здесь один и тот же инструмент
    // разрешён для одного пути и запрещён для другого.
    let gw = gateway_with_canon(ENFORCE_PATH_PREFIX).await;

    let inside = gw
        .client
        .call_tool(call(
            "alpha__write_file",
            serde_json::json!({"path": r"C:\work\zastava\notes.md", "content": "ok"}),
        ))
        .await
        .expect("разрешённый путь обязан пройти");
    assert!(text_of(&inside).contains("wrote"), "{:?}", inside);

    // Отказ приходит как tool-level ошибка (модель должна его прочитать и
    // понять), а не как протокольная — иначе клиент отрендерит её непрозрачно.
    let outside = gw
        .client
        .call_tool(call(
            "alpha__write_file",
            serde_json::json!({"path": "C:/Users/alice/.ssh/id_ed25519", "content": "pwned"}),
        ))
        .await
        .expect("отказ политики — это результат, а не обрыв протокола");
    assert_eq!(outside.is_error, Some(true), "{outside:?}");
    assert!(
        text_of(&outside).contains("zastava policy"),
        "{:?}",
        text_of(&outside)
    );
    assert!(
        !text_of(&outside).contains("wrote"),
        "downstream не должен был получить вызов: {:?}",
        text_of(&outside)
    );

    // Оба вызова обязаны быть в аудите — и разрешённый, и отклонённый.
    let records = wait_records(&gw.log_path, 2).await;
    let decisions: Vec<&str> = records
        .iter()
        .filter(|r| r.is_call())
        .map(|r| r.decision.as_str())
        .collect();
    assert!(decisions.contains(&"allow"), "{decisions:?}");
    assert!(decisions.contains(&"deny"), "{decisions:?}");
}

#[tokio::test]
async fn journal_feeds_learn_which_produces_a_rule_that_enforces() {
    // Полный круг продукта: наблюдение → черновик правила → реальное сужение.
    // Каждое звено проверено по отдельности, но ценность даёт именно круг.
    let observe = r#"
[servers.alpha]
command = "unused-in-tests"
[policy]
mode = "warn"
"#;
    let gw = gateway_with_canon(observe).await;
    for _ in 0..2 {
        gw.client
            .call_tool(call(
                "alpha__write_file",
                serde_json::json!({
                    "path": "C:/work/zastava/crates/core/src/lib.rs",
                    "content": "секретное содержимое файла"
                }),
            ))
            .await
            .expect("warn-режим не блокирует");
    }
    let records = wait_records(&gw.log_path, 2).await;

    // 1. В журнале лежит граница, а не данные.
    let call_record = records.iter().find(|r| r.is_call()).expect("call record");
    assert_eq!(
        call_record.canonical_subset.get("path").map(String::as_str),
        Some("C:/work/zastava/crates/…"),
        "{:?}",
        call_record.canonical_subset
    );
    assert!(
        !call_record.canonical_subset.contains_key("content"),
        "содержимое файла не должно попадать в журнал: {:?}",
        call_record.canonical_subset
    );

    // 2. learn превращает наблюдение в аргументное правило.
    let config = Config::from_toml_str(observe).expect("config");
    let learned = zastava_core::learn::suggest(&records, &config);
    let proposal = learned
        .proposals
        .iter()
        .find(|p| p.sig == "alpha__write_file")
        .expect("правило для наблюдённого инструмента");
    assert!(
        proposal.is_narrowed(),
        "learn обязан сузить по пути: {proposal:?}"
    );

    // 3. Сгенерированное правило реально работает на сыром аргументе.
    let enforced = format!(
        "[servers.alpha]
command = \"unused-in-tests\"
[policy]
mode = \"enforce\"
{}",
        learned.toml_snippet
    );
    let parsed = Config::from_toml_str(&enforced).expect("сниппет обязан быть валидным конфигом");
    let engine = PolicyEngine::from_config(&parsed.policy);
    // Граница теперь глубже (буква диска — корень, а не компонент),
    // поэтому «внутри» означает внутри наблюдавшегося каталога.
    let inside = serde_json::json!({"path": r"C:\work\zastava\crates\other.rs"});
    let outside = serde_json::json!({"path": "C:/Users/alice/.ssh/id"});
    assert!(!engine
        .decide("alpha", "write_file", inside.as_object().unwrap())
        .blocks());
    assert!(engine
        .decide("alpha", "write_file", outside.as_object().unwrap())
        .blocks());
}

#[tokio::test]
async fn weakening_the_policy_on_reload_leaves_an_audit_trail() {
    // Тихо отредактировать конфиг и снять контроль — самый дешёвый способ
    // обойти заставу. Он остаётся возможным (это файл пользователя), но
    // обязан быть ЗАМЕТНЫМ при чтении журнала.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("zastava.toml");
    std::fs::write(&config_path, ENFORCE_ALLOW_ALL).unwrap();
    let config = Config::from_toml_str(ENFORCE_ALLOW_ALL).unwrap();

    let log_dir = tempfile::tempdir().unwrap();
    let log_path = log_dir.path().join("calls.jsonl");
    let log = logger::start(log_path.clone(), logger::DEFAULT_MAX_LOG_BYTES);

    let policy = Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy)));
    let _watch = zastava_proxy::reload::watch(
        config_path.clone(),
        zastava_proxy::reload::ReloadTargets {
            policy: policy.clone(),
            canon: Arc::new(RwLock::new(zastava_core::CanonRules::default())),
            log: Some(log),
        },
    )
    .unwrap();

    // enforce + правило → warn без правил: ослабление по обоим признакам.
    std::fs::write(
        &config_path,
        "[servers.alpha]
command = \"unused-in-tests\"
[policy]
mode = \"warn\"
",
    )
    .unwrap();

    let mut marker = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let records = logger::read_records(&log_path).unwrap_or_default();
        if let Some(found) = records.iter().find(|r| r.tool == "policy_weakened") {
            marker = Some(found.clone());
            break;
        }
    }
    let marker = marker.expect("ослабление политики обязано попасть в журнал");
    assert!(!marker.is_call(), "это маркер события, а не вызов");
    let detail = marker.matched_rule.clone().unwrap_or_default();
    assert!(
        detail.contains("enforce -> warn"),
        "маркер обязан называть причину: {detail}"
    );
    assert!(detail.contains("rules 1 -> 0"), "{detail}");
}

#[tokio::test]
async fn canon_rules_are_found_by_the_raw_tool_name_not_the_escaped_one() {
    // Находка верификации M3: политика решает по СЫРЫМ именам, а канонизация
    // искала правило по ЭКРАНИРОВАННОМУ. Downstream, добавивший в имя символ
    // вне whitelist, выпадал из своего точечного правила и попадал под общий
    // (более широкий) — то есть недоверенная сторона решала, сколько её
    // аргументов уедет в журнал открыто.
    let config_toml = r#"
[servers.alpha]
command = "unused-in-tests"

[[canon.rules]]
sig = "alpha__read:file"
keys = ["collection"]
"#;
    let gw = gateway_with_canon(config_toml).await;

    // Инструмента с таким именем у фикстуры нет — downstream ответит ошибкой,
    // но запись в аудит появится, а вместе с ней и канонический поднабор.
    let _ = gw
        .client
        .call_tool(call(
            "alpha__read:file",
            serde_json::json!({"collection": "notes", "repo": "me/other"}),
        ))
        .await;

    let records = wait_records(&gw.log_path, 1).await;
    let record = records.iter().find(|r| r.is_call()).expect("call record");
    assert!(
        record.canonical_subset.contains_key("collection"),
        "точечное правило обязано найтись: {:?}",
        record.canonical_subset
    );
    assert!(
        !record.canonical_subset.contains_key("repo"),
        "общий whitelist не должен применяться поверх точечного правила: {:?}",
        record.canonical_subset
    );
    assert!(
        record.name_sanitized,
        "факт экранирования имени фиксируется"
    );
}

#[tokio::test]
async fn downstream_error_codes_survive_the_proxy() {
    // Раньше любая ошибка downstream'а схлопывалась в internal_error, и клиент
    // не мог отличить «такого ресурса нет» от «сломался прокси»: чтение
    // несуществующего ресурса выглядело внутренней аварией гейтвея. Код
    // ошибки — часть контракта протокола, посредник не вправе его терять.
    let mut downstreams = HashMap::new();
    downstreams.insert("rich".to_string(), serve_fixture(RichFixture).await);
    let client = gateway_over(downstreams, 2_000).await;

    // Прогреваем карту владельцев: ресурсы маршрутизируются по ней.
    let _ = client.list_resources(Default::default()).await;

    let err = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new("mem://broken"))
        .await
        .expect_err("фикстура обязана ответить ошибкой");

    let text = err.to_string();
    assert!(
        !text.contains("Internal error") && !text.contains("-32603"),
        "код downstream'а не должен подменяться внутренней ошибкой: {text}"
    );
    assert!(
        text.contains("deleted"),
        "сообщение downstream'а должно дойти до клиента: {text}"
    );
}

#[tokio::test]
async fn zastava_refuses_reverse_requests_instead_of_answering_for_the_user() {
    // До M2-full клиент-роль была юнит-типом `()`, а дефолты rmcp УСПЕШНЫ:
    // на roots/list уходило Ok(пустой список), на elicitation — Ok(Decline).
    // То есть застава отвечала downstream'у ОТ ИМЕНИ пользователя, ничего у
    // него не спросив, и сервер не мог отличить это от решения человека.
    let gw = gateway_with(WARN_NO_RULES, 5_000, false).await;
    let result = gw
        .client
        .call_tool(call("alpha__ask_roots", serde_json::json!({})))
        .await
        .expect("вызов доходит до downstream'а");

    let text = text_of(&result);
    assert!(
        !text.contains("ok: 0 roots"),
        "нельзя отвечать «у пользователя нет корней» вместо него: {text}"
    );
    assert!(
        text.starts_with("err:"),
        "downstream обязан получить честный отказ: {text}"
    );
    assert!(
        text.contains("does not forward") || text.contains("roots/list"),
        "отказ должен объяснять причину: {text}"
    );
}

/// Клиент, запоминающий пришедшие progress-уведомления.
///
/// Дефолтный `()` их молча выбрасывает, поэтому проверить перевод токенов им
/// нельзя.
#[derive(Clone, Default)]
struct RecordingClient {
    seen: std::sync::Arc<std::sync::Mutex<Vec<(rmcp::model::ProgressToken, f64)>>>,
}

impl rmcp::handler::client::ClientHandler for RecordingClient {
    async fn on_progress(
        &self,
        params: rmcp::model::ProgressNotificationParam,
        _context: rmcp::service::NotificationContext<rmcp::service::RoleClient>,
    ) {
        self.seen
            .lock()
            .expect("seen lock")
            .push((params.progress_token, params.progress));
    }
}

#[tokio::test]
async fn progress_from_downstream_reaches_the_client_with_its_own_token() {
    // rmcp, отправляя запрос вниз, БЕЗУСЛОВНО подставляет собственный
    // progress-токен: прокинуть клиентский невозможно. Значит downstream шлёт
    // уведомления на свой токен, а клиент ждёт свой — без перевода прогресс
    // либо теряется, либо адресуется в пустоту.
    let bridge = zastava_proxy::downstream::ProgressBridge::new();

    // Фикстура и гейтвей обязаны делить ОДИН мост, иначе переводить нечем.
    let (fixture_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = ProgressFixture::new("prog").serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let ds = DownstreamHandler::with_progress("prog", UpstreamSlot::new(), bridge.clone())
        .serve(fixture_io)
        .await
        .expect("downstream client");

    let mut downstreams = HashMap::new();
    downstreams.insert("prog".to_string(), ds);

    // Политика разрешает только `work`. Отклонённый вызов НЕ уходит вниз —
    // это и разводит счётчики токенов у клиента и у downstream'а, иначе они
    // идут в ногу от нуля и совпадают случайно (тест бы вырождался).
    let policy_toml = r#"
[servers.prog]
command = "unused-in-tests"
[policy]
mode = "enforce"
default = "deny"
[[policy.allow]]
sig = "prog__work"
"#;
    let config = Config::from_toml_str(policy_toml).unwrap();
    let gateway = Gateway::with_options(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        None,
        Duration::from_millis(5_000),
        Duration::from_millis(2_000),
        GatewayOptions {
            progress: bridge,
            ..GatewayOptions::default()
        },
    );
    let (client_io, gw_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = gateway.serve(gw_io).await {
            let _ = running.waiting().await;
        }
    });

    let recorder = RecordingClient::default();
    let seen = recorder.seen.clone();
    let client = recorder.serve(client_io).await.expect("recording client");

    // Отклоняемый вызов: клиентский счётчик токенов сдвигается, downstream
    // о нём вообще не узнаёт.
    let _ = client
        .call_tool(call("prog__forbidden", serde_json::json!({})))
        .await;

    // Шлём запрос НИЗКОУРОВНЕВО, чтобы узнать токен, который rmcp назначил
    // клиенту: именно с ним и надо сравнивать пришедшие уведомления. Через
    // `call_tool` токен остался бы невидимым, и тест доказывал бы только факт
    // доставки, а не перевод.
    let handle = client
        .send_cancellable_request(
            rmcp::model::ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(call(
                "prog__work",
                serde_json::json!({}),
            ))),
            rmcp::service::PeerRequestOptions::no_options(),
        )
        .await
        .expect("запрос уходит");
    let expected_token = handle.progress_token.clone();
    let response = handle.await_response().await.expect("ответ приходит");
    let rmcp::model::ServerResult::CallToolResult(result) = response else {
        panic!("ожидали результат вызова инструмента: {response:?}");
    };
    let answer = text_of(&result);
    assert!(answer.starts_with("done"), "{answer}");
    // Фикстура назвала СВОЙ токен. Если он совпал с клиентским, проверка
    // перевода ничего не значит — тогда тест обязан упасть, а не молча пройти.
    let downstream_token = answer
        .split("token=")
        .nth(1)
        .expect("фикстура называет свой токен")
        .to_string();
    let client_token = format!("{expected_token:?}");
    assert_ne!(
        downstream_token, client_token,
        "токены совпали — проверка перевода вырождается в тавтологию"
    );

    // Уведомления идут отдельным потоком от ответа — даём им дойти.
    let mut got = Vec::new();
    for _ in 0..100 {
        got = seen.lock().expect("seen lock").clone();
        if got.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        got.len(),
        3,
        "клиент должен увидеть все три уведомления: {got:?}"
    );
    let steps: Vec<f64> = got.iter().map(|(_, p)| *p).collect();
    assert_eq!(steps, vec![1.0, 2.0, 3.0], "порядок и значения сохраняются");

    // Токен обязан быть ТОТ, который клиент ждёт, — иначе он не свяжет
    // уведомление со своим вызовом.
    for (token, step) in &got {
        assert_eq!(
            token, &expected_token,
            "уведомление о шаге {step} пришло с ЧУЖИМ токеном: клиент не свяжет              его со своим вызовом (downstream-токен вместо клиентского)"
        );
    }
}

#[tokio::test]
async fn progress_of_one_server_never_lands_in_a_call_to_another() {
    // P1 ревью M2-full. Счётчик progress-токенов у rmcp свой на каждого пира и
    // начинается с нуля, поэтому n-й запрос к серверу A и n-й запрос к серверу
    // B получают ОДИН И ТОТ ЖЕ токен. Пока мост был ключом только по токену:
    // регистрации затирали друг друга, прогресс уезжал в чужой вызов, часть
    // уведомлений пропадала совсем — а враждебный сервер мог веером вписывать
    // СВОЙ текст в ход чужой операции (клиент показывает `message` человеку).
    let bridge = zastava_proxy::downstream::ProgressBridge::new();

    let mut downstreams = HashMap::new();
    for name in ["a", "b"] {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let fixture = ProgressFixture::new(name);
        tokio::spawn(async move {
            if let Ok(running) = fixture.serve(server_io).await {
                let _ = running.waiting().await;
            }
        });
        let ds = DownstreamHandler::with_progress(name, UpstreamSlot::new(), bridge.clone())
            .serve(client_io)
            .await
            .expect("downstream client");
        downstreams.insert(name.to_string(), ds);
    }

    let policy_toml = r#"
[servers.a]
command = "unused-in-tests"
[servers.b]
command = "unused-in-tests"
"#;
    let config = Config::from_toml_str(policy_toml).unwrap();
    let gateway = Gateway::with_options(
        downstreams,
        Arc::new(RwLock::new(PolicyEngine::from_config(&config.policy))),
        None,
        Duration::from_millis(5_000),
        Duration::from_millis(2_000),
        GatewayOptions {
            progress: bridge,
            ..GatewayOptions::default()
        },
    );
    let (client_io, gw_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Ok(running) = gateway.serve(gw_io).await {
            let _ = running.waiting().await;
        }
    });

    let recorder = RecordingMessages::default();
    let seen = recorder.seen.clone();
    let client = recorder.serve(client_io).await.expect("recording client");

    // Два вызова, по одному к каждому серверу. Их downstream-токены совпадут.
    let mut tokens = HashMap::new();
    let mut handles = Vec::new();
    for name in ["a", "b"] {
        let handle = client
            .send_cancellable_request(
                rmcp::model::ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(
                    call(&format!("{name}__work"), serde_json::json!({})),
                )),
                rmcp::service::PeerRequestOptions::no_options(),
            )
            .await
            .expect("запрос уходит");
        tokens.insert(name, handle.progress_token.clone());
        handles.push(handle);
    }
    for handle in handles {
        let _ = handle.await_response().await;
    }

    // Ждём, пока уведомления дойдут.
    let mut got = Vec::new();
    for _ in 0..100 {
        got = seen.lock().expect("seen").clone();
        if got.len() >= 6 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        got.len(),
        6,
        "оба вызова должны отчитаться по три раза: {got:?}"
    );
    for (token, message) in &got {
        let owner = if message.starts_with("a#") { "a" } else { "b" };
        assert_eq!(
            token,
            tokens.get(owner).expect("токен вызова"),
            "уведомление «{message}» уехало в вызов к ДРУГОМУ серверу"
        );
    }
}

/// Клиент, запоминающий токен и текст каждого уведомления.
#[derive(Clone, Default)]
struct RecordingMessages {
    seen: std::sync::Arc<std::sync::Mutex<Vec<(rmcp::model::ProgressToken, String)>>>,
}

impl rmcp::handler::client::ClientHandler for RecordingMessages {
    async fn on_progress(
        &self,
        params: rmcp::model::ProgressNotificationParam,
        _context: rmcp::service::NotificationContext<rmcp::service::RoleClient>,
    ) {
        self.seen
            .lock()
            .expect("seen")
            .push((params.progress_token, params.message.unwrap_or_default()));
    }
}

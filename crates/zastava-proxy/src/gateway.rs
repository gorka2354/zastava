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
    ContentBlock, ErrorData, GetPromptRequestParams, GetPromptResponse, Implementation,
    ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse, Resource, ResultType,
    ServerCapabilities, ServerInfo, ServerResult, Tool,
};
use rmcp::service::{
    PeerRequestOptions, RequestContext, RoleClient, RoleServer, RunningService, ServiceError,
};
use rmcp::ServerHandler;
use serde_json::{Map, Value};
use zastava_core::config::{sanitize_name, NS_SEP};
use zastava_core::signature::{full_args_hash, CANON_VERSION};
use zastava_core::{CallRecord, CanonRules, Decision, PolicyEngine, Verdict};

use crate::logger::LogHandle;
use crate::util::{next_event_id, now_rfc3339};

/// Подключённый downstream (клиентская сторона rmcp).
pub type DownstreamService = RunningService<RoleClient, crate::downstream::DownstreamHandler>;

/// Итог форварда для записи в журнал.
struct CallOutcome {
    duration_ms: u64,
    result_bytes: u64,
    is_error: bool,
    /// Мы перестали ждать ответа: побочный эффект мог состояться.
    abandoned: bool,
    /// Почему всё закончилось именно так.
    reason: Option<String>,
}

impl CallOutcome {
    fn blocked() -> Self {
        Self {
            duration_ms: 0,
            result_bytes: 0,
            is_error: false,
            abandoned: false,
            reason: None,
        }
    }
    fn failed(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            result_bytes: 0,
            is_error: true,
            abandoned: false,
            reason: None,
        }
    }
    fn abandoned(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            result_bytes: 0,
            is_error: true,
            abandoned: true,
            reason: None,
        }
    }

    /// Дополняет исход причиной: «таймаут» и «downstream умер» — разные
    /// факты, и различать их обязан журнал, а не только текст для модели.
    fn because(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Собирает инструменты одного downstream'а, обходя пагинацию с потолками.
///
/// Свой цикл вместо `list_all_tools`: тот крутится, пока downstream отдаёт
/// курсор, а враждебный (или просто сломанный) сервер может повторять один и
/// тот же курсор вечно — время ограничил бы таймаут, а память нет.
async fn list_one(name: &str, ds: &DownstreamService) -> Result<Vec<Tool>, ServiceError> {
    let mut collected = Vec::new();
    let mut cursor: Option<String> = None;
    for page in 0..MAX_LIST_PAGES {
        let mut params = PaginatedRequestParams::default();
        params.cursor = cursor.clone();
        let result = ds.list_tools(Some(params)).await?;
        for mut tool in result.tools {
            tool.name = format!("{name}{NS_SEP}{}", tool.name).into();
            collected.push(tool);
            if collected.len() >= MAX_TOOLS_PER_SERVER {
                tracing::warn!(
                    server = %name,
                    limit = MAX_TOOLS_PER_SERVER,
                    "downstream exceeded the tool limit; listing truncated"
                );
                return Ok(collected);
            }
        }
        let next = result.next_cursor.map(|c| c.to_string());
        match next {
            None => return Ok(collected),
            // Повтор курсора — верный признак сломанной или враждебной
            // пагинации: дальше будет бесконечный цикл.
            Some(next) if Some(&next) == cursor.as_ref() => {
                tracing::warn!(server = %name, "downstream repeats its pagination cursor; listing truncated");
                return Ok(collected);
            }
            Some(next) => {
                cursor = Some(next);
                if page + 1 == MAX_LIST_PAGES {
                    tracing::warn!(
                        server = %name,
                        pages = MAX_LIST_PAGES,
                        "downstream exceeded the page limit; listing truncated"
                    );
                }
            }
        }
    }
    Ok(collected)
}

/// Опции журналирования гейтвея.
#[derive(Debug, Clone, Default)]
pub struct GatewayOptions {
    /// Прозрачный режим: политика отключена (журнал — нет).
    pub passthrough: bool,
    /// Писать в журнал полные аргументы вызовов (опт-ин, см. `log.log_args`).
    pub log_args: bool,
    /// Правила канонизации аргументов.
    pub canon: Arc<RwLock<CanonRules>>,
    /// Общий с downstream-обработчиками мост progress-токенов.
    pub progress: crate::downstream::ProgressBridge,
    /// Карта «URI ресурса → сервер». Общая с хабом list_changed: тот обязан
    /// её чистить, когда downstream переставил свои ресурсы.
    pub resource_owners: Arc<RwLock<HashMap<String, String>>>,
}

/// Гейтвей: реализация ServerHandler поверх множества downstream'ов.
pub struct Gateway {
    downstreams: HashMap<String, DownstreamService>,
    policy: Arc<RwLock<PolicyEngine>>,
    log: Option<LogHandle>,
    call_timeout: Duration,
    list_timeout: Duration,
    passthrough: bool,
    log_args: bool,
    /// Правила канонизации аргументов для журнала. За RwLock по той же
    /// причине, что и политика: `zastava.toml` может измениться на ходу, и
    /// журнал обязан писаться по действующим правилам, а не по стартовым.
    canon: Arc<RwLock<CanonRules>>,
    /// Возможности, вычисленные из реальных downstream'ов: объявлять
    /// resources/prompts, которых ни у кого нет, — врать клиенту.
    capabilities: ServerCapabilities,
    /// URI ресурса → downstream-владелец. Ресурсы адресуются URI, а не
    /// именем, поэтому префиксовать их нельзя (сломается адресация) —
    /// маршрутизируем по карте владения, которую обновляем на листинге.
    resource_owners: Arc<RwLock<HashMap<String, String>>>,
    /// Перевод progress-токенов: downstream шлёт свой, клиент ждёт свой.
    progress: crate::downstream::ProgressBridge,
}

/// Потолки обхода пагинации downstream'а. Без них downstream, повторяющий
/// один и тот же курсор, крутит цикл по кешу rmcp без сетевых запросов —
/// таймаут ограничивает время, но не память (находка верификации M1: ~1.8 млн
/// Tool-структур за секунду → OOM гейтвея).
const MAX_LIST_PAGES: usize = 50;
/// Псевдо-имена в журнале для не-инструментальных действий: чтение ресурса и
/// получение промпта — тоже действия агента и обязаны быть в аудите.
/// Символы взяты из того же whitelist, что и обычные имена: иначе наши
/// собственные метки экранировались бы санитайзером и записи ложно
/// помечались как name_sanitized.
const RESOURCE_PSEUDO_TOOL: &str = "zastava.resource";
const PROMPT_PSEUDO_TOOL: &str = "zastava.prompt.";
const MAX_TOOLS_PER_SERVER: usize = 2_000;
/// Во сколько раз прогресс может продлить ожидание сверх базового бюджета.
/// Потолок нужен, потому что источник продления — недоверенный downstream.
const MAX_PROGRESS_EXTENSIONS: u32 = 10;

impl Gateway {
    /// Собирает гейтвей. `passthrough` отключает политику (но НЕ журнал —
    /// отключённый контроль обязан оставлять след, находка ревью M1).
    pub fn new(
        downstreams: HashMap<String, DownstreamService>,
        policy: Arc<RwLock<PolicyEngine>>,
        log: Option<LogHandle>,
        call_timeout: Duration,
        list_timeout: Duration,
        passthrough: bool,
    ) -> Self {
        Self::with_options(
            downstreams,
            policy,
            log,
            call_timeout,
            list_timeout,
            GatewayOptions {
                passthrough,
                ..GatewayOptions::default()
            },
        )
    }

    /// Полный конструктор: дополнительно принимает опции журналирования.
    pub fn with_options(
        downstreams: HashMap<String, DownstreamService>,
        policy: Arc<RwLock<PolicyEngine>>,
        log: Option<LogHandle>,
        call_timeout: Duration,
        list_timeout: Duration,
        options: GatewayOptions,
    ) -> Self {
        let capabilities = merged_capabilities(&downstreams);
        Self {
            downstreams,
            policy,
            log,
            call_timeout,
            list_timeout,
            passthrough: options.passthrough,
            log_args: options.log_args,
            canon: options.canon,
            progress: options.progress,
            capabilities,
            resource_owners: options.resource_owners,
        }
    }

    /// Обновляет карту «URI ресурса → сервер», опрашивая downstream'ы.
    async fn refresh_resource_owners(&self) -> Vec<Resource> {
        // Порядок обхода ДЕТЕРМИНИРОВАННЫЙ — по имени сервера.
        //
        // Правило «первый объявивший URI им и владеет» само по себе разумно,
        // но обход `HashMap` рандомизирован, и «первый» получался подбросом
        // монеты: верификация M2-full намерила, что враждебный сервер,
        // объявивший чужой URI, перехватывал чтения в 17 случаях из 40. При
        // сортировке победитель всегда один и тот же, а конфликт видно в
        // аудите.
        let mut ordered: Vec<_> = self.downstreams.iter().collect();
        ordered.sort_by_key(|(name, _)| (*name).clone());
        let per_server = ordered.into_iter().map(|(name, ds)| async move {
            let listed = tokio::time::timeout(self.list_timeout, ds.list_all_resources()).await;
            (name.clone(), listed)
        });
        let mut resources = Vec::new();
        let mut owners = HashMap::new();
        for (name, listed) in futures::future::join_all(per_server).await {
            match listed {
                Ok(Ok(listed)) => {
                    for resource in listed {
                        // Первый объявивший URI им и владеет: одинаковые URI
                        // у разных серверов — конфликт, о котором сообщаем.
                        match owners.entry(resource.uri.clone()) {
                            std::collections::hash_map::Entry::Vacant(slot) => {
                                slot.insert(name.clone());
                                resources.push(resource);
                            }
                            std::collections::hash_map::Entry::Occupied(taken) => {
                                tracing::warn!(
                                    uri = %resource.uri,
                                    owner = %taken.get(),
                                    duplicate = %name,
                                    "resource URI claimed by two servers; keeping the first"
                                );
                                // Два сервера на один URI — это либо ошибка
                                // настройки, либо попытка перехватить чужой
                                // ресурс. И то и другое человек должен
                                // увидеть, а не искать в stderr.
                                self.mark_uri_conflict(taken.get(), &name, &resource.uri);
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(server = %name, error = %e, "resources/list failed; server excluded")
                }
                Err(_) => {
                    tracing::warn!(server = %name, "resources/list timed out; server excluded")
                }
            }
        }
        *self.resource_owners.write().expect("owners lock poisoned") = owners;
        resources
    }

    /// Кто отдаёт этот URI. При промахе — один рефреш карты (ресурс мог
    /// появиться после последнего листинга), потом отказ.
    async fn owner_of(&self, uri: &str) -> Option<String> {
        if let Some(owner) = self
            .resource_owners
            .read()
            .expect("owners lock poisoned")
            .get(uri)
        {
            return Some(owner.clone());
        }
        self.refresh_resource_owners().await;
        let owner = self
            .resource_owners
            .read()
            .expect("owners lock poisoned")
            .get(uri)
            .cloned();
        owner
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
        // Имена приходят от клиента/downstream. Пишем в журнал только
        // экранированные: иначе управляющие последовательности переписывают
        // вывод `stats`/`learn`, где отчёт об этих же вызовах и читают.
        let (raw_server, raw_tool) = (server, tool);
        let (server, server_dirty) = sanitize_name(server);
        let (tool, tool_dirty) = sanitize_name(tool);
        let (decision_str, enforced, matched_rule) = match decision {
            Some(d) => (
                match d.verdict {
                    Verdict::Allow => "allow",
                    Verdict::Deny => "deny",
                },
                d.enforced,
                d.matched_rule.clone(),
            ),
            // Различаем «контроль выключен» и «этот тип действия политика
            // v0.1 не покрывает» (ресурсы и промпты): в журнале это разные
            // факты, и путать их нельзя.
            None if self.passthrough => ("passthrough", false, None),
            None => ("ungated", false, None),
        };
        log.write(CallRecord {
            ts: now_rfc3339(),
            id: next_event_id(),
            canonical_subset: {
                // Гуард живёт ровно на время вычисления и НЕ переживает await.
                // Ищем по СЫРЫМ именам: экранирование меняет имя инструмента,
                // и точечное правило `[[canon.rules]]` переставало находиться,
                // откатываясь на более широкий whitelist — то есть недоверенная
                // сторона решала бы, сколько её аргументов уедет в журнал
                // открыто (находка ревью M3).
                let canon = self.canon.read().expect("canon lock poisoned");
                canon.subset(raw_server, raw_tool, args)
            },
            server,
            tool,
            name_sanitized: server_dirty || tool_dirty,
            canon_version: CANON_VERSION,
            args_hash: full_args_hash(args),
            // Полные аргументы — только по явному опт-ину: до маскировки
            // секретов (M4) сюда попадёт всё, включая токены.
            args: self.log_args.then(|| Value::Object(args.clone())),
            decision: decision_str.to_string(),
            enforced,
            matched_rule,
            duration_ms: outcome.duration_ms,
            result_bytes: outcome.result_bytes,
            is_error: outcome.is_error,
            abandoned: outcome.abandoned,
            reason: outcome.reason,
            ..Default::default()
        });
    }

    /// Отклонённый вызов тоже событие аудита: без этого перебор имён серверов
    /// и инструментов не оставляет в журнале следа (находка ревью M1).
    fn record_rejected(&self, server: &str, tool: &str, reason: &str) {
        let Some(log) = &self.log else { return };
        let (server, server_dirty) = sanitize_name(server);
        let (tool, tool_dirty) = sanitize_name(tool);
        log.write(CallRecord {
            ts: now_rfc3339(),
            id: next_event_id(),
            server,
            tool,
            name_sanitized: server_dirty || tool_dirty,
            decision: "rejected".to_string(),
            matched_rule: Some(reason.to_string()),
            is_error: true,
            ..Default::default()
        });
    }

    /// Пишет в аудит конфликт владения URI ресурса.
    fn mark_uri_conflict(&self, owner: &str, duplicate: &str, uri: &str) {
        let Some(log) = &self.log else { return };
        let (owner, o_dirty) = sanitize_name(owner);
        let (duplicate, d_dirty) = sanitize_name(duplicate);
        let (uri, u_dirty) = sanitize_name(uri);
        let mut record = CallRecord::marker(
            now_rfc3339(),
            next_event_id(),
            "resource_uri_conflict",
            Some(format!(
                "{uri}: принадлежит {owner}, заявлен также {duplicate}"
            )),
        );
        record.name_sanitized = o_dirty || d_dirty || u_dirty;
        log.write(record);
    }

    /// Пишет в аудит, что сервер выпал из выдачи.
    fn mark_unreachable(&self, server: &str, detail: &str) {
        let Some(log) = &self.log else { return };
        let (server, s_dirty) = sanitize_name(server);
        // `detail` содержит сообщение об ошибке ОТ СЕРВЕРА — экранируем и его.
        let (detail, d_dirty) = sanitize_name(detail);
        let mut record = CallRecord::marker(
            now_rfc3339(),
            next_event_id(),
            "downstream_unreachable",
            Some(format!("{server}: {detail}")),
        );
        record.name_sanitized = s_dirty || d_dirty;
        log.write(record);
    }

    fn tool_error(message: String) -> CallToolResponse {
        // CallToolResult::error сам ставит resultType=complete и isError.
        CallToolResult::error(vec![ContentBlock::text(message)]).into()
    }
}

/// Переносит ошибку downstream'а наверх, СОХРАНЯЯ её код.
///
/// Раньше здесь стоял безусловный `internal_error`, и клиент не мог отличить
/// «такого ресурса нет» от «сломался прокси»: любое чтение несуществующего
/// ресурса выглядело внутренней аварией гейтвея. Код ошибки — часть контракта
/// протокола, и посредник не имеет права его терять (находка разведки M2-full).
///
/// Транспортные ошибки кодом не обладают — они и остаются internal_error,
/// потому что для клиента это действительно авария посредника.
fn downstream_error(context: String, e: &ServiceError) -> ErrorData {
    match e {
        ServiceError::McpError(inner) => ErrorData::new(
            inner.code,
            format!("{context}: {}", inner.message),
            inner.data.clone(),
        ),
        other => ErrorData::internal_error(format!("{context}: {other}"), None),
    }
}

/// Объявляем только те возможности, которые реально есть хотя бы у одного
/// downstream: обещать клиенту resources/prompts, которых никто не отдаёт, —
/// врать (клиент будет слать запросы, на которые придёт пустота).
/// Объявляет ли хоть один downstream уведомления об изменении своего списка.
///
/// Честность та же, что и с самими возможностями: обещать клиенту, что мы
/// сообщим об изменениях, когда об этом никто не сообщает нам, — враньё.
fn any_list_changed(
    downstreams: &HashMap<String, DownstreamService>,
    pick: impl Fn(&ServerCapabilities) -> Option<bool>,
) -> bool {
    downstreams
        .values()
        .filter_map(|ds| ds.peer_info())
        .any(|info| pick(&info.capabilities) == Some(true))
}

fn merged_capabilities(downstreams: &HashMap<String, DownstreamService>) -> ServerCapabilities {
    let mut capabilities = ServerCapabilities::builder()
        .enable_tools()
        .enable_prompts()
        .enable_resources()
        .build();
    let peers: Vec<_> = downstreams
        .values()
        .filter_map(|ds| ds.peer_info())
        .collect();
    if !peers.iter().any(|p| p.capabilities.resources.is_some()) {
        capabilities.resources = None;
    }
    if !peers.iter().any(|p| p.capabilities.prompts.is_some()) {
        capabilities.prompts = None;
    }

    // listChanged объявляем, только если о своих изменениях сообщает хотя бы
    // один downstream. Обещать клиенту уведомления, которых нам никто не шлёт,
    // — то же враньё, что и объявлять чужие возможности.
    if let Some(tools) = capabilities.tools.as_mut() {
        tools.list_changed = any_list_changed(downstreams, |c| {
            c.tools.as_ref().and_then(|t| t.list_changed)
        })
        .then_some(true);
    }
    if let Some(resources) = capabilities.resources.as_mut() {
        resources.list_changed = any_list_changed(downstreams, |c| {
            c.resources.as_ref().and_then(|r| r.list_changed)
        })
        .then_some(true);
    }
    if let Some(prompts) = capabilities.prompts.as_mut() {
        prompts.list_changed = any_list_changed(downstreams, |c| {
            c.prompts.as_ref().and_then(|p| p.list_changed)
        })
        .then_some(true);
    }
    capabilities
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = self.capabilities.clone();
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
        // Опрашиваем downstream'ы ПАРАЛЛЕЛЬНО и с коротким собственным
        // таймаутом: последовательный обход с бюджетом вызова означал бы,
        // что N молчащих серверов держат tools/list N × call_timeout и клиент
        // отваливается раньше нас (находка верификации M1).
        let per_server = self.downstreams.iter().map(|(name, ds)| async move {
            let listed = tokio::time::timeout(self.list_timeout, list_one(name, ds)).await;
            (name.as_str(), listed)
        });
        let mut tools = Vec::new();
        for (name, listed) in futures::future::join_all(per_server).await {
            match listed {
                Ok(Ok(listed)) => tools.extend(listed),
                // Сервер выпал из выдачи — его инструменты просто исчезают,
                // и человек видит «инструмента нет», а не «сервер недоступен».
                // Для аудита это разные факты, поэтому событие, а не только
                // stderr, который никто не читает (находка ревью M2-full).
                Ok(Err(e)) => {
                    tracing::warn!(server = %name, error = %e, "tools/list failed; server excluded");
                    self.mark_unreachable(name, &format!("tools/list failed: {e}"));
                }
                Err(_) => {
                    tracing::warn!(
                        server = %name,
                        timeout_ms = self.list_timeout.as_millis() as u64,
                        "tools/list timed out; server excluded from this listing"
                    );
                    self.mark_unreachable(
                        name,
                        &format!(
                            "tools/list timed out after {}ms",
                            self.list_timeout.as_millis()
                        ),
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
        context: RequestContext<RoleServer>,
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

        // Стадия форварда. Ждём ответ сами, чтобы одинаково обработать ОБА
        // повода перестать ждать: наш таймаут и отмену со стороны клиента
        // (ESC в клиенте шлёт notifications/cancelled). В обоих случаях
        // downstream обязан узнать об отмене — простой drop future его не
        // отменяет, и он молча доводит побочный эффект до конца.
        let mut downstream_req = request;
        downstream_req.name = tool.to_string().into();
        let started = Instant::now();
        // Опции ПУСТЫЕ — и это осознанно.
        //
        // `with_timeout(..).reset_timeout_on_progress()` выглядит ровно тем,
        // что нужно, но rmcp применяет эти опции ТОЛЬКО внутри
        // `RequestHandle::await_response()`, а мы его не зовём: ждём ответа
        // сами, потому что нам нужен общий `select!` с отменой от клиента.
        // В итоге опции не заводили никакого таймера (продление прогрессом не
        // работало вовсе), но заставляли rmcp класть запись в
        // `progress_timeout_watchers`, которую снимает только `await_response`
        // или `cancel` — на успешном ответе она оставалась навсегда,
        // ~766 байт на вызов (замерено ревью M2-full).
        //
        // Продление таймаута прогрессом реализовано ниже своим циклом.
        let sent = ds
            .send_cancellable_request(
                ClientRequest::CallToolRequest(CallToolRequest::new(downstream_req)),
                PeerRequestOptions::no_options(),
            )
            .await;

        /// Чем закончился форвард вызова вниз.
        ///
        /// Тип существует, чтобы исход НЕ МОГ соврать. Раньше три разных
        /// события — таймаут, отмена клиентом и смерть downstream'а — все
        /// подставляли `ServiceError::UnexpectedResponse`, и в журнал уходило
        /// «failed: Unexpected response type» там, где на самом деле вызов
        /// МОГ СОСТОЯТЬСЯ. Для продукта, чей товар — доказательство
        /// происходившего, это худший сорт ошибки (находка разведки M2-full).
        enum Forwarded {
            /// Downstream ответил — успехом или собственной ошибкой.
            /// Boxed: `ServerResult` заметно больше остальных вариантов.
            Answered(Box<Result<ServerResult, ServiceError>>),
            /// Запрос УШЁЛ, ответа нет. Побочный эффект мог состояться.
            Abandoned(&'static str),
            /// Отправить не удалось: вызов ТОЧНО не состоялся.
            NotSent(ServiceError),
        }

        let forwarded = match sent {
            Err(e) => Forwarded::NotSent(e),
            Ok(mut handle) => {
                // Клиент прислал свой progress-токен только если сам просил
                // прогресса. rmcp подставил вниз СВОЙ токен — связываем их на
                // время вызова; страж снимет связь на любом выходе.
                //
                // Имя сервера в ключе обязательно: счётчик токенов у rmcp свой
                // на каждого пира и начинается с нуля, поэтому у разных
                // downstream'ов они систематически совпадают.
                let registered = context.meta.get_progress_token().map(|client_token| {
                    self.progress.register(
                        server,
                        handle.progress_token.clone(),
                        client_token,
                        context.peer.clone(),
                    )
                });
                let (_progress_guard, progress_tick) = match registered {
                    Some((guard, tick)) => (Some(guard), Some(tick)),
                    None => (None, None),
                };

                enum Stop {
                    Answered(Box<Result<ServerResult, ServiceError>>),
                    Timeout,
                    ClientCancelled,
                    Died,
                }

                // Таймаут отсчитываем сами и ПРОДЛЕВАЕМ его на каждом
                // уведомлении о прогрессе: операция, которая жива и
                // отчитывается, не должна обрываться по общему бюджету, а
                // замолчавшая — должна.
                let stop = {
                    let started_waiting = tokio::time::Instant::now();
                    // Абсолютный потолок ожидания. Продление привязано к паре
                    // (сервер, токен), но ТОКЕН В УВЕДОМЛЕНИИ ВЫБИРАЕТ САМ
                    // СЕРВЕР: враждебному downstream'у достаточно одного
                    // жертвенного вызова, поливающего прогрессом токены своих
                    // же соседних вызовов, чтобы держать их вечно —
                    // верификация M2-full удержала вызов 4.6 с при бюджете
                    // 300 мс. Продление отвечает на вопрос «операция жива?»,
                    // а не «можно ли ждать бесконечно».
                    let hard_deadline =
                        started_waiting + self.call_timeout * MAX_PROGRESS_EXTENSIONS;
                    let mut deadline = started_waiting + self.call_timeout;
                    loop {
                        let tick = progress_tick.clone();
                        let progressed = async {
                            match tick {
                                Some(tick) => tick.notified().await,
                                // Клиент прогресса не просил — продлевать
                                // нечем, ждём только дедлайна.
                                None => std::future::pending().await,
                            }
                        };
                        tokio::select! {
                            biased;
                            _ = context.ct.cancelled() => break Stop::ClientCancelled,
                            _ = tokio::time::sleep_until(deadline) => break Stop::Timeout,
                            _ = tokio::time::sleep_until(hard_deadline) => break Stop::Timeout,
                            _ = progressed => {
                                deadline = (tokio::time::Instant::now() + self.call_timeout)
                                    .min(hard_deadline);
                                continue;
                            }
                            answered = &mut handle.rx => break match answered {
                                Ok(result) => Stop::Answered(Box::new(result)),
                                // Канал закрыт, а ответа не было: downstream
                                // исчез посреди запроса. Запрос уже ушёл к нему.
                                Err(_) => Stop::Died,
                            },
                        }
                    }
                };
                match stop {
                    Stop::Answered(result) => Forwarded::Answered(result),
                    Stop::Timeout => {
                        let _ = handle
                            .cancel(Some("zastava call timeout".to_string()))
                            .await;
                        Forwarded::Abandoned("zastava call timeout")
                    }
                    Stop::ClientCancelled => {
                        let _ = handle.cancel(Some("client cancelled".to_string())).await;
                        Forwarded::Abandoned("client cancelled")
                    }
                    // Отменять некому — процесс уже мёртв.
                    Stop::Died => Forwarded::Abandoned("downstream died mid-request"),
                }
            }
        };
        let duration_ms = started.elapsed().as_millis() as u64;

        let outcome = match forwarded {
            Forwarded::Abandoned(reason) => {
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome::abandoned(duration_ms).because(reason),
                );
                return Ok(Self::tool_error(format!(
                    "stopped waiting for downstream '{server}' after {duration_ms}ms ({reason}); \
                     the call may still have taken effect"
                )));
            }
            Forwarded::NotSent(e) => {
                // Отличается от предыдущего случая принципиально: сюда вызов
                // не дошёл, побочного эффекта быть не могло.
                self.record(
                    server,
                    tool,
                    &args,
                    decision.as_ref(),
                    CallOutcome::failed(duration_ms)
                        .because(sanitize_name(&format!("unreachable: {e}")).0),
                );
                return Ok(Self::tool_error(format!(
                    "could not reach downstream '{server}': {e}; the call did not happen"
                )));
            }
            Forwarded::Answered(result) => *result,
        };

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
                        reason: None,
                    },
                );
                Ok(response)
            }
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        // URI не префиксуем: он адрес, а не имя. Маршрутизация — по карте
        // владения, которую этот же вызов и обновляет.
        let resources = self.refresh_resource_owners().await;
        Ok(ListResourcesResult::with_all_items(resources)
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let per_server = self.downstreams.iter().map(|(name, ds)| async move {
            let listed =
                tokio::time::timeout(self.list_timeout, ds.list_all_resource_templates()).await;
            (name.as_str(), listed)
        });
        let mut templates = Vec::new();
        for (name, listed) in futures::future::join_all(per_server).await {
            match listed {
                Ok(Ok(listed)) => templates.extend(listed),
                Ok(Err(e)) => {
                    tracing::warn!(server = %name, error = %e, "resources/templates/list failed")
                }
                Err(_) => tracing::warn!(server = %name, "resources/templates/list timed out"),
            }
        }
        Ok(ListResourceTemplatesResult::with_all_items(templates)
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let uri = request.uri.clone();
        let Some(owner) = self.owner_of(&uri).await else {
            self.record_rejected("?", &uri, "resource URI owned by no downstream");
            return Err(ErrorData::invalid_params(
                format!("unknown resource: {uri}"),
                None,
            ));
        };
        let Some(ds) = self.downstreams.get(&owner) else {
            return Err(ErrorData::internal_error(
                format!("downstream '{owner}' is gone"),
                None,
            ));
        };

        // Чтение ресурса — тоже действие агента, и оно обязано попасть в
        // аудит. Политика v0.1 покрывает только инструменты (см. design-док),
        // поэтому здесь фиксируем факт, а не решение.
        let started = Instant::now();
        let outcome = tokio::time::timeout(self.call_timeout, ds.read_resource(request)).await;
        let duration_ms = started.elapsed().as_millis() as u64;
        let mut args = Map::new();
        args.insert("uri".to_string(), Value::String(uri.clone()));

        match outcome {
            Ok(Ok(mut result)) => {
                // Тот же урок спайка, что и для tools/call: downstream мог
                // договориться о старой ревизии, и rmcp вычистил resultType —
                // клиент на 2026-07-28 отвергает такой ответ. Поймано живым
                // клиентом на реальном сервере, тесты с фикстурами молчали.
                result.result_type = Some(ResultType::COMPLETE);
                let result_bytes = serde_json::to_string(&result)
                    .map(|s| s.len() as u64)
                    .unwrap_or(0);
                self.record(
                    &owner,
                    RESOURCE_PSEUDO_TOOL,
                    &args,
                    None,
                    CallOutcome {
                        duration_ms,
                        result_bytes,
                        is_error: false,
                        abandoned: false,
                        reason: None,
                    },
                );
                Ok(ReadResourceResponse::Complete(result))
            }
            Ok(Err(e)) => {
                self.record(
                    &owner,
                    RESOURCE_PSEUDO_TOOL,
                    &args,
                    None,
                    CallOutcome::failed(duration_ms),
                );
                Err(downstream_error(
                    format!("downstream '{owner}' failed to read {uri}"),
                    &e,
                ))
            }
            Err(_) => {
                self.record(
                    &owner,
                    RESOURCE_PSEUDO_TOOL,
                    &args,
                    None,
                    CallOutcome::abandoned(duration_ms),
                );
                Err(ErrorData::internal_error(
                    format!("downstream '{owner}' timed out reading {uri}"),
                    None,
                ))
            }
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        // Промпты адресуются ИМЕНЕМ — префиксуем так же, как инструменты.
        let per_server = self.downstreams.iter().map(|(name, ds)| async move {
            let listed = tokio::time::timeout(self.list_timeout, ds.list_all_prompts()).await;
            (name.as_str(), listed)
        });
        let mut prompts = Vec::new();
        for (name, listed) in futures::future::join_all(per_server).await {
            match listed {
                Ok(Ok(listed)) => {
                    for mut prompt in listed {
                        prompt.name = format!("{name}{NS_SEP}{}", prompt.name);
                        prompts.push(prompt);
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(server = %name, error = %e, "prompts/list failed; server excluded")
                }
                Err(_) => tracing::warn!(server = %name, "prompts/list timed out; server excluded"),
            }
        }
        Ok(ListPromptsResult::with_all_items(prompts)
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let full_name = request.name.clone();
        let Some((server, prompt)) = full_name.split_once(NS_SEP) else {
            self.record_rejected(&full_name, "", "prompt name without namespace");
            return Err(ErrorData::invalid_params(
                format!("prompt without namespace: {full_name}"),
                None,
            ));
        };
        let Some(ds) = self.downstreams.get(server) else {
            self.record_rejected(server, prompt, "unknown downstream server");
            return Err(ErrorData::invalid_params(
                format!("unknown downstream: {server}"),
                None,
            ));
        };
        let mut downstream_req = request;
        downstream_req.name = prompt.to_string();

        let started = Instant::now();
        let outcome = tokio::time::timeout(self.call_timeout, ds.get_prompt(downstream_req)).await;
        let duration_ms = started.elapsed().as_millis() as u64;
        let args = Map::new();

        match outcome {
            Ok(Ok(mut result)) => {
                result.result_type = Some(ResultType::COMPLETE);
                let result_bytes = serde_json::to_string(&result)
                    .map(|s| s.len() as u64)
                    .unwrap_or(0);
                self.record(
                    server,
                    &format!("{PROMPT_PSEUDO_TOOL}{prompt}"),
                    &args,
                    None,
                    CallOutcome {
                        duration_ms,
                        result_bytes,
                        is_error: false,
                        abandoned: false,
                        reason: None,
                    },
                );
                Ok(GetPromptResponse::Complete(result))
            }
            Ok(Err(e)) => {
                self.record(
                    server,
                    &format!("{PROMPT_PSEUDO_TOOL}{prompt}"),
                    &args,
                    None,
                    CallOutcome::failed(duration_ms),
                );
                Err(downstream_error(
                    format!("downstream '{server}' failed to get prompt"),
                    &e,
                ))
            }
            Err(_) => {
                self.record(
                    server,
                    &format!("{PROMPT_PSEUDO_TOOL}{prompt}"),
                    &args,
                    None,
                    CallOutcome::abandoned(duration_ms),
                );
                Err(ErrorData::internal_error(
                    format!("downstream '{server}' timed out getting prompt"),
                    None,
                ))
            }
        }
    }
}

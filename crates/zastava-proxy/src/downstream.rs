//! Клиент-роль заставы: то, чем она разговаривает с downstream-серверами.
//!
//! До M2-full здесь стоял юнит-тип `()`, и это было не «не реализовано», а
//! **реализовано неправильно**. Дефолтные ответы `ClientHandler` в rmcp —
//! успешные: на `roots/list` уходит `Ok(пустой список)`, на `elicitation` —
//! `Ok(Decline)`. То есть застава отвечала downstream-серверу ОТ ИМЕНИ
//! пользователя, ничего у него не спросив, и сервер не мог отличить это от
//! настоящего решения человека.
//!
//! Для продукта, чей тезис — «ты должен знать, что произошло», такое молчаливое
//! замещение пользователя хуже отказа. Поэтому здесь честный `method_not_found`:
//! возможностей мы downstream'у не объявляли, значит корректный ответ на такой
//! запрос — «этого метода тут нет», а не выдуманное согласие или отказ.
//!
//! Пересылка обратных запросов настоящему клиенту (W4) сюда же и придёт —
//! слот апстрим-пира заведён заранее именно под неё.

// SEP-2577 объявил sampling и roots устаревшими, и rmcp пометил их типы
// `deprecated`. Реализовать эти методы мы всё равно ОБЯЗАНЫ: они есть в
// трейте, и пока downstream может их позвать, наш ответ должен быть честным
// отказом, а не выдуманным согласием от имени пользователя. Сам rmcp внутри
// поступает так же (`#![expect(deprecated)]` в service/server.rs).
#![allow(deprecated)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rmcp::handler::client::ClientHandler;
use rmcp::model::{
    CreateMessageRequestParams, CreateMessageResult, ElicitRequestParams, ElicitResult, ErrorData,
    ListRootsResult, ProgressNotificationParam, ProgressToken,
};
use rmcp::service::{NotificationContext, Peer, RequestContext, RoleClient, RoleServer};
use tokio::sync::watch;
use zastava_core::CallRecord;

use crate::logger::LogHandle;
use crate::util::{next_event_id, now_rfc3339};

/// Слот с пиром НАСТОЯЩЕГО клиента.
///
/// Существует из-за порядка инициализации: downstream'ы поднимаются на старте,
/// а `Peer<RoleServer>` рождается только когда клиент подключился и гейтвей
/// начал обслуживание. Сконструировать пир заранее нельзя (`Peer::new` —
/// `pub(crate)` в rmcp), поэтому обработчик клиент-роли получает пустой слот и
/// ждёт, пока его заполнят.
#[derive(Clone)]
pub struct UpstreamSlot {
    tx: watch::Sender<Option<Peer<RoleServer>>>,
}

impl Default for UpstreamSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamSlot {
    /// Пустой слот.
    pub fn new() -> Self {
        Self {
            tx: watch::channel(None).0,
        }
    }

    /// Заполняет слот. Вызывается один раз, когда клиент подключился.
    pub fn set(&self, peer: Peer<RoleServer>) {
        self.tx.send_replace(Some(peer));
    }

    /// Пир, если клиент уже подключён. Для уведомлений: их шлют
    /// «выстрелил и забыл», ждать ради них нельзя.
    pub fn try_get(&self) -> Option<Peer<RoleServer>> {
        self.tx.borrow().clone()
    }

    /// Ждёт появления пира не дольше `timeout`. Для ЗАПРОСОВ: downstream
    /// имеет право спросить сразу после своего старта, когда клиент ещё не
    /// пришёл, и мгновенный отказ в этой гонке был бы несправедлив.
    pub async fn wait(&self, timeout: Duration) -> Option<Peer<RoleServer>> {
        if let Some(peer) = self.try_get() {
            return Some(peer);
        }
        let mut rx = self.tx.subscribe();
        tokio::time::timeout(timeout, async move {
            // changed() просыпается на любой send; нас интересует непустое.
            while rx.changed().await.is_ok() {
                if let Some(peer) = rx.borrow_and_update().clone() {
                    return Some(peer);
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }
}

/// Мост прогресса: соответствие токенов downstream'а и клиента.
///
/// Нужен из-за того, как rmcp устроен внутри: отправляя запрос вниз, он
/// БЕЗУСЛОВНО подставляет собственный progress-токен — прокинуть клиентский
/// нельзя. Downstream шлёт уведомления на свой токен, а клиент ждёт свой, и
/// без перевода прогресс либо теряется, либо адресуется в пустоту.
///
/// Заодно это граница доверия: downstream может прислать уведомление на ЧУЖОЙ
/// токен (свой или выдуманный). Незарегистрированный токен просто не имеет
/// соответствия и дальше не идёт — подделать чужой прогресс нельзя.
#[derive(Clone, Default)]
pub struct ProgressBridge {
    relays: Arc<Mutex<HashMap<ProgressToken, Relay>>>,
}

impl std::fmt::Debug for ProgressBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Содержимое не печатаем: там пиры и токены живых вызовов.
        f.write_str("ProgressBridge")
    }
}

#[derive(Clone)]
struct Relay {
    client_token: ProgressToken,
    client: Peer<RoleServer>,
}

impl ProgressBridge {
    /// Пустой мост.
    pub fn new() -> Self {
        Self::default()
    }

    /// Связывает токен downstream'а с токеном клиента на время вызова.
    ///
    /// Возвращает страж: соответствие снимается на ЛЮБОМ выходе из вызова —
    /// успех, ошибка, таймаут, отмена. Без этого карта росла бы вечно.
    pub fn register(
        &self,
        downstream_token: ProgressToken,
        client_token: ProgressToken,
        client: Peer<RoleServer>,
    ) -> ProgressGuard {
        self.relays.lock().expect("progress lock poisoned").insert(
            downstream_token.clone(),
            Relay {
                client_token,
                client,
            },
        );
        ProgressGuard {
            bridge: self.clone(),
            token: downstream_token,
        }
    }

    /// Переводит уведомление downstream'а клиенту. Молча игнорирует
    /// незнакомый токен.
    async fn relay(&self, mut params: ProgressNotificationParam) {
        let relay = {
            let map = self.relays.lock().expect("progress lock poisoned");
            map.get(&params.progress_token).cloned()
        };
        let Some(relay) = relay else { return };
        params.progress_token = relay.client_token;
        if let Err(e) = relay.client.notify_progress(params).await {
            tracing::debug!(error = %e, "could not relay progress to the client");
        }
    }
}

/// Снимает соответствие токенов, когда вызов закончился.
pub struct ProgressGuard {
    bridge: ProgressBridge,
    token: ProgressToken,
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        self.bridge
            .relays
            .lock()
            .expect("progress lock poisoned")
            .remove(&self.token);
    }
}

/// Пауза схлопывания уведомлений об изменении списков.
const LIST_CHANGED_DEBOUNCE: Duration = Duration::from_millis(200);
/// Не чаще одного исходящего уведомления на категорию за это окно.
const LIST_CHANGED_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Какой список изменился.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListKind {
    /// Инструменты.
    Tools,
    /// Ресурсы.
    Resources,
    /// Промпты.
    Prompts,
}

impl ListKind {
    fn as_str(self) -> &'static str {
        match self {
            ListKind::Tools => "tools",
            ListKind::Resources => "resources",
            ListKind::Prompts => "prompts",
        }
    }
}

/// Пересылка уведомлений «список изменился» от downstream'ов клиенту.
///
/// Три обязанности, и каждая появилась не просто так:
///
/// 1. **Схлопывание.** Пять downstream'ов, разом сообщивших об изменении, — это
///    пять уведомлений клиенту об одном и том же факте «список инструментов
///    больше не тот». Наружу уходит одно на категорию.
/// 2. **Потолок частоты.** Уведомление заставляет клиента перезапросить списки,
///    а гейтвей — веерно опросить ВСЕ downstream'ы с пагинацией. Недоверенный
///    сервер, шлющий их шквалом, иначе управляет нагрузкой всего гейтвея.
///    Мы не отбрасываем сигнал, а откладываем — потерять изменение хуже.
/// 3. **Чистка кеша владельцев ресурсов.** Ресурсы маршрутизируются по карте
///    «URI → сервер», построенной на листинге. Если downstream переставил свои
///    ресурсы, карта врёт и чтение уходит к бывшему владельцу.
#[derive(Clone, Default)]
pub struct ListChangedHub {
    inner: Arc<HubInner>,
}

#[derive(Default)]
struct HubInner {
    upstream: UpstreamSlot,
    /// Та же карта, что у гейтвея: её надо чистить при смене ресурсов.
    resource_owners: Arc<RwLock<HashMap<String, String>>>,
    log: Option<LogHandle>,
    state: Mutex<HashMap<ListKind, CategoryState>>,
}

#[derive(Default)]
struct CategoryState {
    /// Уведомление уже запланировано — второе планировать не нужно.
    scheduled: bool,
    last_sent: Option<Instant>,
}

impl std::fmt::Debug for ListChangedHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ListChangedHub")
    }
}

impl ListChangedHub {
    /// Хаб, знающий, куда пересылать и какой кеш чистить.
    pub fn new(
        upstream: UpstreamSlot,
        resource_owners: Arc<RwLock<HashMap<String, String>>>,
        log: Option<LogHandle>,
    ) -> Self {
        Self {
            inner: Arc::new(HubInner {
                upstream,
                resource_owners,
                log,
                state: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Принимает уведомление от downstream'а `server`.
    pub fn notify(&self, server: &str, kind: ListKind) {
        // В аудит пишем КАЖДОЕ входящее с именем источника, даже если наружу
        // уйдёт одно: расследование не должно терять, кто именно менялся.
        if let Some(log) = &self.inner.log {
            log.write(CallRecord::marker(
                now_rfc3339(),
                next_event_id(),
                "list_changed",
                Some(format!("{server}: {}", kind.as_str())),
            ));
        }

        if kind == ListKind::Resources {
            // Карта владельцев построена на прошлом листинге и теперь может
            // врать: чтение ушло бы к бывшему владельцу ресурса.
            self.inner
                .resource_owners
                .write()
                .expect("resource owners lock poisoned")
                .clear();
        }

        let delay = {
            let mut state = self.inner.state.lock().expect("hub lock poisoned");
            let entry = state.entry(kind).or_default();
            if entry.scheduled {
                return;
            }
            entry.scheduled = true;
            // Пауза схлопывания плюс, если нужно, доводка до потолка частоты.
            let since_last = entry
                .last_sent
                .map(|t| t.elapsed())
                .unwrap_or(LIST_CHANGED_MIN_INTERVAL);
            let cooldown = LIST_CHANGED_MIN_INTERVAL.saturating_sub(since_last);
            LIST_CHANGED_DEBOUNCE.max(cooldown)
        };

        let inner = self.inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            {
                let mut state = inner.state.lock().expect("hub lock poisoned");
                let entry = state.entry(kind).or_default();
                entry.scheduled = false;
                entry.last_sent = Some(Instant::now());
            }
            // Уведомление — «выстрелил и забыл»: если клиента ещё нет, ждать
            // ради него нечего, списки он и так запросит при подключении.
            let Some(client) = inner.upstream.try_get() else {
                return;
            };
            let sent = match kind {
                ListKind::Tools => client.notify_tool_list_changed().await,
                ListKind::Resources => client.notify_resource_list_changed().await,
                ListKind::Prompts => client.notify_prompt_list_changed().await,
            };
            if let Err(e) = sent {
                // Клиент вправе не принимать такие уведомления — это не наша
                // авария.
                tracing::debug!(kind = kind.as_str(), error = %e, "client did not accept list_changed");
            }
        });
    }
}

/// Обработчик клиент-роли для одного downstream-сервера.
#[derive(Clone)]
pub struct DownstreamHandler {
    /// Имя сервера из конфига — попадает в диагностику и (позже) в аудит.
    name: String,
    /// Пир настоящего клиента; заполняется после его подключения.
    #[allow(dead_code)] // задействуется в W4 (пересылка обратных запросов)
    upstream: UpstreamSlot,
    /// Перевод progress-токенов между downstream'ом и клиентом.
    progress: ProgressBridge,
    /// Пересылка уведомлений об изменении списков.
    lists: ListChangedHub,
}

impl DownstreamHandler {
    /// Создаёт обработчик для сервера `name`.
    pub fn new(name: impl Into<String>, upstream: UpstreamSlot) -> Self {
        Self::with_progress(name, upstream, ProgressBridge::new())
    }

    /// Тот же обработчик, но с общим мостом прогресса.
    pub fn with_progress(
        name: impl Into<String>,
        upstream: UpstreamSlot,
        progress: ProgressBridge,
    ) -> Self {
        Self::with_bridges(name, upstream, progress, ListChangedHub::default())
    }

    /// Полный конструктор: общие мост прогресса и хаб списков.
    pub fn with_bridges(
        name: impl Into<String>,
        upstream: UpstreamSlot,
        progress: ProgressBridge,
        lists: ListChangedHub,
    ) -> Self {
        Self {
            name: name.into(),
            upstream,
            progress,
            lists,
        }
    }

    /// Честный отказ на запрос, который застава пока не пересылает.
    ///
    /// Именно ошибка, а не выдуманный успех: downstream должен видеть, что
    /// возможности нет, и решать сам — а не считать, что пользователь ему
    /// отказал или что у пользователя нет ни одного корневого каталога.
    fn not_forwarded(&self, method: &str) -> ErrorData {
        tracing::warn!(
            server = %self.name,
            method,
            "downstream asked the client for something zastava does not forward yet"
        );
        // `ErrorData::method_not_found::<M>()` требует const-строку типом;
        // нам нужно имя метода в рантайме, поэтому собираем код руками.
        ErrorData::new(
            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
            format!("zastava does not forward '{method}' to the client"),
            None,
        )
    }
}

impl ClientHandler for DownstreamHandler {
    async fn create_message(
        &self,
        _params: CreateMessageRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<CreateMessageResult, ErrorData> {
        // Sampling объявлен устаревшим (SEP-2577) — пересылать его в v0.1
        // смысла нет, но и притворяться, что мы его выполнили, нельзя.
        Err(self.not_forwarded("sampling/createMessage"))
    }

    async fn list_roots(
        &self,
        _context: RequestContext<RoleClient>,
    ) -> Result<ListRootsResult, ErrorData> {
        // Дефолт rmcp вернул бы Ok(пустой список) — то есть соврал бы, что у
        // пользователя нет ни одного корневого каталога.
        Err(self.not_forwarded("roots/list"))
    }

    async fn create_elicitation(
        &self,
        _request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        // Дефолт rmcp вернул бы Ok(Decline) — отказ от имени человека,
        // которого никто не спрашивал.
        Err(self.not_forwarded("elicitation/create"))
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        // Уведомление — не запрос: отвечать некому и ждать нечего. Просто
        // переводим токен и отправляем дальше.
        self.progress.relay(params).await;
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.lists.notify(&self.name, ListKind::Tools);
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.lists.notify(&self.name, ListKind::Resources);
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.lists.notify(&self.name, ListKind::Prompts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owners_with(uri: &str, server: &str) -> Arc<RwLock<HashMap<String, String>>> {
        let map = Arc::new(RwLock::new(HashMap::new()));
        map.write()
            .unwrap()
            .insert(uri.to_string(), server.to_string());
        map
    }

    #[tokio::test]
    async fn resource_list_changed_drops_the_owner_cache() {
        // Ресурсы маршрутизируются по карте «URI → сервер», построенной на
        // прошлом листинге. Если downstream переставил свои ресурсы, карта
        // врёт, и чтение уходит к БЫВШЕМУ владельцу.
        let owners = owners_with("mem://note", "alpha");
        let hub = ListChangedHub::new(UpstreamSlot::new(), owners.clone(), None);

        hub.notify("alpha", ListKind::Resources);
        assert!(
            owners.read().unwrap().is_empty(),
            "карта владельцев обязана сброситься"
        );
    }

    #[tokio::test]
    async fn tool_list_changed_leaves_the_resource_cache_alone() {
        // Смена списка ИНСТРУМЕНТОВ маршрутизацию ресурсов не затрагивает:
        // сбрасывать карту здесь значило бы дарить downstream'у способ
        // заставлять гейтвей веерно перелистывать всех.
        let owners = owners_with("mem://note", "alpha");
        let hub = ListChangedHub::new(UpstreamSlot::new(), owners.clone(), None);

        hub.notify("alpha", ListKind::Tools);
        assert_eq!(owners.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_burst_from_many_servers_is_coalesced_into_one_send() {
        // Пять downstream'ов, разом сообщивших об изменении, — это один факт
        // «список больше не тот», а не пять. Наружу должно уйти одно
        // уведомление на категорию.
        let hub = ListChangedHub::new(
            UpstreamSlot::new(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
        );
        for server in ["a", "b", "c", "d", "e"] {
            hub.notify(server, ListKind::Tools);
        }
        let scheduled = hub
            .inner
            .state
            .lock()
            .unwrap()
            .get(&ListKind::Tools)
            .map(|s| s.scheduled)
            .unwrap_or(false);
        assert!(scheduled, "отправка запланирована");
        // Ровно одна запись на категорию — значит запланирована одна отправка,
        // а не пять.
        assert_eq!(hub.inner.state.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn every_incoming_notification_is_audited_with_its_source() {
        // Наружу уходит одно уведомление, но расследование не должно терять,
        // КТО именно менялся.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calls.jsonl");
        let log = crate::logger::start(path.clone(), crate::logger::DEFAULT_MAX_LOG_BYTES);
        let hub = ListChangedHub::new(
            UpstreamSlot::new(),
            Arc::new(RwLock::new(HashMap::new())),
            Some(log),
        );

        hub.notify("alpha", ListKind::Tools);
        hub.notify("beta", ListKind::Tools);

        let mut records = Vec::new();
        for _ in 0..100 {
            records = crate::logger::read_records(&path).unwrap_or_default();
            if records.len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let sources: Vec<String> = records
            .iter()
            .filter(|r| r.tool == "list_changed")
            .filter_map(|r| r.matched_rule.clone())
            .collect();
        assert_eq!(sources.len(), 2, "обе записи на месте: {sources:?}");
        assert!(
            sources.iter().any(|s| s.starts_with("alpha")),
            "{sources:?}"
        );
        assert!(sources.iter().any(|s| s.starts_with("beta")), "{sources:?}");
    }

    #[tokio::test]
    async fn empty_slot_times_out_instead_of_hanging() {
        let slot = UpstreamSlot::new();
        assert!(slot.try_get().is_none());
        let waited = slot.wait(Duration::from_millis(50)).await;
        assert!(waited.is_none(), "пустой слот обязан отпустить по таймауту");
    }
}

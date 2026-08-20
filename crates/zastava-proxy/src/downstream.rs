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
/// **Ключ карты — ПАРА (сервер, токен), и это принципиально.** Счётчик
/// progress-токенов у rmcp свой на каждого пира и начинается с нуля, поэтому
/// n-й запрос к серверу A и n-й запрос к серверу B получают ОДИН И ТОТ ЖЕ
/// токен. Пока ключом был только токен, происходило два разных зла (оба
/// воспроизведены ревью M2-full):
/// - без всякого умысла регистрации двух серверов затирали друг друга, прогресс
///   уезжал в чужой вызов, а страж снимал чужую запись;
/// - враждебный сервер, зная, что токены — маленькие предсказуемые целые, слал
///   уведомления веером и вписывал СВОЙ текст в ход чужого вызова: клиент
///   показывает `message` человеку, и получался канал обмана оператора.
#[derive(Clone, Default)]
pub struct ProgressBridge {
    relays: Arc<Mutex<HashMap<RelayKey, Relay>>>,
}

/// Кто именно прислал токен. Без имени сервера токены разных downstream'ов
/// систематически совпадают.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RelayKey {
    server: String,
    token: ProgressToken,
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
    /// Будится на каждом переведённом уведомлении. Гейтвей ждёт этот сигнал,
    /// чтобы продлить свой таймаут: операция, которая ЖИВА и отчитывается,
    /// не должна обрываться по общему бюджету.
    tick: Arc<tokio::sync::Notify>,
}

impl ProgressBridge {
    /// Пустой мост.
    pub fn new() -> Self {
        Self::default()
    }

    /// Связывает токен downstream'а с токеном клиента на время вызова.
    ///
    /// Возвращает страж (соответствие снимается на ЛЮБОМ выходе из вызова —
    /// успех, ошибка, таймаут, отмена; без этого карта росла бы вечно) и
    /// сигнал, который будится на каждом переведённом уведомлении.
    pub fn register(
        &self,
        server: &str,
        downstream_token: ProgressToken,
        client_token: ProgressToken,
        client: Peer<RoleServer>,
    ) -> (ProgressGuard, Arc<tokio::sync::Notify>) {
        let tick = Arc::new(tokio::sync::Notify::new());
        let key = RelayKey {
            server: server.to_string(),
            token: downstream_token,
        };
        self.relays.lock().expect("progress lock poisoned").insert(
            key.clone(),
            Relay {
                client_token,
                client,
                tick: tick.clone(),
            },
        );
        (
            ProgressGuard {
                bridge: self.clone(),
                key,
            },
            tick,
        )
    }

    /// Переводит уведомление downstream'а клиенту. Молча игнорирует
    /// незнакомую пару (сервер, токен).
    async fn relay(&self, server: &str, mut params: ProgressNotificationParam) {
        let key = RelayKey {
            server: server.to_string(),
            token: params.progress_token.clone(),
        };
        let relay = {
            let map = self.relays.lock().expect("progress lock poisoned");
            map.get(&key).cloned()
        };
        let Some(relay) = relay else { return };
        params.progress_token = relay.client_token;
        // Сигналим ДО отправки: гейтвею важен сам факт «downstream жив».
        relay.tick.notify_one();
        if let Err(e) = relay.client.notify_progress(params).await {
            tracing::debug!(error = %e, "could not relay progress to the client");
        }
    }
}

/// Снимает соответствие токенов, когда вызов закончился.
pub struct ProgressGuard {
    bridge: ProgressBridge,
    key: RelayKey,
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        self.bridge
            .relays
            .lock()
            .expect("progress lock poisoned")
            .remove(&self.key);
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
    /// Кто и сколько раз сообщил за текущее окно. Копится в памяти ровно на
    /// время окна и уходит в журнал одной сводкой: атрибуция сохраняется, а
    /// стоимость перестаёт зависеть от щедрости downstream'а.
    seen: HashMap<String, u64>,
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
    ///
    /// Всё, что здесь делается, ограничено по частоте — и это не оптимизация,
    /// а требование безопасности. Уведомление шлёт САМ СЕРВЕР: ни модель, ни
    /// политика в этом не участвуют, стоит оно ~85 байт, а раньше каждое
    /// порождало запись в журнале. Ревью M2-full воспроизвело: 76 725
    /// уведомлений за 5 секунд — это ~4.4 МБ/с роста журнала, и вся история
    /// (50 МБ × 6 поколений) вытиралась ротацией за минуту вместе с записями
    /// о заблокированных вызовах. То есть недоверенный сервер бесплатно и
    /// тихо уничтожал главный товар продукта.
    ///
    /// Атрибуцию при этом терять нельзя, поэтому в журнал уходит не каждое
    /// уведомление, а СВОДКА за окно: «сервер X, категория Y, N уведомлений».
    pub fn notify(&self, server: &str, kind: ListKind) {
        let mut state = self.inner.state.lock().expect("hub lock poisoned");
        let entry = state.entry(kind).or_default();
        *entry.seen.entry(server.to_string()).or_insert(0) += 1;

        if entry.scheduled {
            // Окно уже открыто: и сводка, и сброс кеша, и уведомление наружу
            // произойдут по его истечении — ровно по разу.
            return;
        }
        entry.scheduled = true;
        let since_last = entry
            .last_sent
            .map(|t| t.elapsed())
            .unwrap_or(LIST_CHANGED_MIN_INTERVAL);
        let cooldown = LIST_CHANGED_MIN_INTERVAL.saturating_sub(since_last);
        let delay = LIST_CHANGED_DEBOUNCE.max(cooldown);
        drop(state);

        let inner = self.inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;

            let seen = {
                let mut state = inner.state.lock().expect("hub lock poisoned");
                let entry = state.entry(kind).or_default();
                entry.scheduled = false;
                entry.last_sent = Some(Instant::now());
                std::mem::take(&mut entry.seen)
            };

            // Сводка: кто и сколько раз сообщил за окно. Одна запись вместо
            // тысяч, но источники все названы.
            if let Some(log) = &inner.log {
                let mut sources: Vec<String> =
                    seen.iter().map(|(s, n)| format!("{s}×{n}")).collect();
                sources.sort();
                log.write(CallRecord::marker(
                    now_rfc3339(),
                    next_event_id(),
                    "list_changed",
                    Some(format!("{}: {}", kind.as_str(), sources.join(", "))),
                ));
            }

            if kind == ListKind::Resources {
                // Чистим ТОЛЬКО записи тех серверов, что сообщили об
                // изменении. Полный `clear()` позволял одному downstream'у
                // обнулить маршрутизацию чужих ресурсов и заставить гейтвей
                // веерно перелистывать ВСЕХ на каждом последующем чтении
                // (находка ревью M2-full).
                let mut owners = inner
                    .resource_owners
                    .write()
                    .expect("resource owners lock poisoned");
                owners.retain(|_, owner| !seen.contains_key(owner));
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

/// Пишет в журнал СВОДКУ за окно вместо записи на каждое событие.
///
/// Появился потому, что одно и то же лечение понадобилось дважды. Сперва
/// шквалом `list_changed` недоверенный сервер вымывал ротацией весь аудит;
/// это закрыли схлопыванием — и той же волной открыли заново через
/// `reverse_request_refused`, который писал запись на КАЖДЫЙ обратный запрос
/// (верификация M2-full: 13 тыс. запросов/с, 1.4 МБ/с журнала, вся история
/// стиралась за три с половиной минуты).
///
/// Общий тип, чтобы третьего раза не было: любое событие, частоту которого
/// задаёт downstream, обязано идти через него.
#[derive(Clone)]
pub struct SummaryLog {
    event: &'static str,
    log: Option<LogHandle>,
    state: Arc<Mutex<SummaryState>>,
}

#[derive(Default)]
struct SummaryState {
    scheduled: bool,
    /// Ключ → сколько раз за окно. Ключ строит вызывающий (обычно
    /// «сервер: что просил»), поэтому атрибуция не теряется.
    seen: HashMap<String, u64>,
}

impl SummaryLog {
    /// Сводка событий `event` в журнал `log`.
    pub fn new(event: &'static str, log: Option<LogHandle>) -> Self {
        Self {
            event,
            log,
            state: Arc::new(Mutex::new(SummaryState::default())),
        }
    }

    /// Учитывает событие. Запись появится одной сводкой по окончании окна.
    pub fn record(&self, key: String) {
        if self.log.is_none() {
            return;
        }
        {
            let mut state = self.state.lock().expect("summary lock poisoned");
            *state.seen.entry(key).or_insert(0) += 1;
            if state.scheduled {
                return;
            }
            state.scheduled = true;
        }

        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SUMMARY_WINDOW).await;
            let seen = {
                let mut state = this.state.lock().expect("summary lock poisoned");
                state.scheduled = false;
                std::mem::take(&mut state.seen)
            };
            let Some(log) = &this.log else { return };
            let mut parts: Vec<String> = seen.iter().map(|(k, n)| format!("{k}×{n}")).collect();
            parts.sort();
            log.write(CallRecord::marker(
                now_rfc3339(),
                next_event_id(),
                this.event,
                Some(parts.join(", ")),
            ));
        });
    }
}

impl std::fmt::Debug for SummaryLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SummaryLog")
    }
}

/// Окно схлопывания для сводок в журнал.
const SUMMARY_WINDOW: Duration = Duration::from_millis(500);

/// Всё общее, что downstream-обработчик получает от гейтвея.
///
/// Отдельный тип, потому что этих связей стало четыре и они одинаковы для
/// всех downstream'ов: тащить их россыпью через `spawn_downstream` значило бы
/// менять сигнатуру при каждом новом мосте.
#[derive(Clone)]
pub struct Shared {
    /// Пир настоящего клиента; заполняется после его подключения.
    pub upstream: UpstreamSlot,
    /// Перевод progress-токенов между downstream'ом и клиентом.
    pub progress: ProgressBridge,
    /// Пересылка уведомлений об изменении списков.
    pub lists: ListChangedHub,
    /// Журнал: отказ downstream'у — тоже событие аудита.
    pub log: Option<LogHandle>,
    /// Сводка отказов обратным запросам. Частоту этих событий задаёт
    /// downstream, поэтому запись на каждое — готовый способ вымыть аудит.
    pub refusals: SummaryLog,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            upstream: UpstreamSlot::default(),
            progress: ProgressBridge::default(),
            lists: ListChangedHub::default(),
            log: None,
            refusals: SummaryLog::new("reverse_request_refused", None),
        }
    }
}

/// Обработчик клиент-роли для одного downstream-сервера.
#[derive(Clone)]
pub struct DownstreamHandler {
    /// Имя сервера из конфига — попадает в диагностику и в аудит.
    name: String,
    shared: Shared,
}

impl DownstreamHandler {
    /// Создаёт обработчик для сервера `name`.
    pub fn new(name: impl Into<String>, shared: Shared) -> Self {
        Self {
            name: name.into(),
            shared,
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
        // Попытка сервера обратиться к пользователю — событие аудита, даже
        // когда мы её отклонили. Иначе «сервер просил у меня доступ к корневым
        // каталогам» останется известным только stderr'у, который никто не
        // читает (находка ревью M2-full).
        //
        // Через СВОДКУ, а не записью на каждый запрос: частоту здесь задаёт
        // downstream, и запись на каждую попытку — готовый способ вымыть
        // ротацией весь аудит (находка верификации M2-full).
        let (server, _) = zastava_core::config::sanitize_name(&self.name);
        self.shared.refusals.record(format!("{server}: {method}"));
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
    fn get_info(&self) -> rmcp::model::ClientInfo {
        // По умолчанию rmcp представляется downstream'у как «rmcp 3.1.3».
        // Сервер, который логирует своих клиентов или ведёт себя по-разному
        // для разных, видел бы библиотеку вместо гейтвея — а через заставу
        // ходит не библиотека, а конкретный посредник с политикой.
        let mut info = rmcp::model::ClientInfo::default();
        info.client_info = rmcp::model::Implementation::new("zastava", env!("CARGO_PKG_VERSION"));
        info
    }

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
        // переводим токен и отправляем дальше. Имя сервера обязательно:
        // без него токены разных downstream'ов сливаются в один ключ.
        self.shared.progress.relay(&self.name, params).await;
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.shared.lists.notify(&self.name, ListKind::Tools);
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.shared.lists.notify(&self.name, ListKind::Resources);
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.shared.lists.notify(&self.name, ListKind::Prompts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ждёт, пока хаб отработает окно схлопывания.
    async fn settle() {
        tokio::time::sleep(LIST_CHANGED_DEBOUNCE + Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn resource_list_changed_evicts_only_the_notifying_server() {
        // Ресурсы маршрутизируются по карте «URI → сервер». Если downstream
        // переставил свои ресурсы, его записи врут. Но чистить ВСЮ карту
        // нельзя: тогда один сервер обнуляет маршрутизацию чужих ресурсов и
        // заставляет гейтвей веерно перелистывать всех на каждом чтении
        // (находка ревью M2-full).
        let owners = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut map = owners.write().unwrap();
            map.insert("mem://alpha-note".to_string(), "alpha".to_string());
            map.insert("mem://beta-note".to_string(), "beta".to_string());
        }
        let hub = ListChangedHub::new(UpstreamSlot::new(), owners.clone(), None);

        hub.notify("alpha", ListKind::Resources);
        settle().await;

        let map = owners.read().unwrap();
        assert!(
            !map.contains_key("mem://alpha-note"),
            "записи сообщившего сервера обязаны уйти: {map:?}"
        );
        assert_eq!(
            map.get("mem://beta-note").map(String::as_str),
            Some("beta"),
            "чужие записи трогать нельзя: {map:?}"
        );
    }

    #[tokio::test]
    async fn tool_list_changed_leaves_the_resource_cache_alone() {
        // Смена списка ИНСТРУМЕНТОВ маршрутизацию ресурсов не затрагивает.
        let owners = Arc::new(RwLock::new(HashMap::new()));
        owners
            .write()
            .unwrap()
            .insert("mem://note".to_string(), "alpha".to_string());
        let hub = ListChangedHub::new(UpstreamSlot::new(), owners.clone(), None);

        hub.notify("alpha", ListKind::Tools);
        settle().await;
        assert_eq!(owners.read().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_flood_cannot_wipe_the_journal() {
        // P1 ревью M2-full: запись в журнал стояла ДО схлопывания, и каждое
        // уведомление порождало запись. Недоверенный сервер за минуту вымывал
        // ротацией всю историю, включая записи о заблокированных вызовах, —
        // то есть бесплатно отключал главный товар продукта.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calls.jsonl");
        let log = crate::logger::start(path.clone(), crate::logger::DEFAULT_MAX_LOG_BYTES);

        // Улика: настоящая запись о заблокированном вызове.
        log.write(CallRecord {
            ts: now_rfc3339(),
            id: "ev-evidence".into(),
            server: "github".into(),
            tool: "create_issue".into(),
            decision: "deny".into(),
            enforced: true,
            ..Default::default()
        });

        let hub = ListChangedHub::new(
            UpstreamSlot::new(),
            Arc::new(RwLock::new(HashMap::new())),
            Some(log),
        );
        for _ in 0..5_000 {
            hub.notify("evil", ListKind::Tools);
        }
        settle().await;

        let records = crate::logger::read_records(&path).unwrap_or_default();
        let list_records = records.iter().filter(|r| r.tool == "list_changed").count();
        assert!(
            list_records <= 2,
            "5000 уведомлений обязаны схлопнуться в сводку, а не в {list_records} записей"
        );
        assert!(
            records.iter().any(|r| r.id == "ev-evidence"),
            "улика обязана уцелеть: {} записей",
            records.len()
        );
    }

    #[tokio::test]
    async fn the_summary_names_every_source() {
        // Наружу уходит одно уведомление и одна запись, но расследование не
        // должно терять, КТО именно менялся и сколько раз.
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
        hub.notify("beta", ListKind::Tools);
        settle().await;

        let records = crate::logger::read_records(&path).unwrap_or_default();
        let summary = records
            .iter()
            .find(|r| r.tool == "list_changed")
            .and_then(|r| r.matched_rule.clone())
            .expect("сводка обязана быть");
        assert!(summary.contains("alpha×1"), "{summary}");
        assert!(summary.contains("beta×2"), "{summary}");
        assert!(summary.contains("tools"), "{summary}");
    }

    #[tokio::test]
    async fn a_flood_of_refusals_collapses_into_one_summary() {
        // Верификация M2-full: `reverse_request_refused` писался на КАЖДЫЙ
        // обратный запрос, и враждебный сервер вымывал ротацией весь аудит за
        // три с половиной минуты — ровно та атака, которую та же волна
        // закрыла для list_changed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calls.jsonl");
        let log = crate::logger::start(path.clone(), crate::logger::DEFAULT_MAX_LOG_BYTES);
        let summary = SummaryLog::new("reverse_request_refused", Some(log));

        for _ in 0..5_000 {
            summary.record("evil: roots/list".to_string());
        }
        summary.record("evil: elicitation/create".to_string());
        tokio::time::sleep(SUMMARY_WINDOW + Duration::from_millis(200)).await;

        let records = crate::logger::read_records(&path).unwrap_or_default();
        let refusals: Vec<&CallRecord> = records
            .iter()
            .filter(|r| r.tool == "reverse_request_refused")
            .collect();
        assert!(
            refusals.len() <= 2,
            "5001 отказ обязан схлопнуться в сводку, а не в {} записей",
            refusals.len()
        );
        let detail = refusals
            .first()
            .and_then(|r| r.matched_rule.clone())
            .expect("сводка");
        assert!(detail.contains("roots/list×5000"), "{detail}");
        assert!(
            detail.contains("elicitation/create×1"),
            "второй метод тоже обязан быть назван: {detail}"
        );
    }

    #[tokio::test]
    async fn empty_slot_times_out_instead_of_hanging() {
        let slot = UpstreamSlot::new();
        assert!(slot.try_get().is_none());
        let waited = slot.wait(Duration::from_millis(50)).await;
        assert!(waited.is_none(), "пустой слот обязан отпустить по таймауту");
    }
}

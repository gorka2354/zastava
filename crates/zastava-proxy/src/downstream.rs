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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::client::ClientHandler;
use rmcp::model::{
    CreateMessageRequestParams, CreateMessageResult, ElicitRequestParams, ElicitResult, ErrorData,
    ListRootsResult, ProgressNotificationParam, ProgressToken,
};
use rmcp::service::{NotificationContext, Peer, RequestContext, RoleClient, RoleServer};
use tokio::sync::watch;

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
        Self {
            name: name.into(),
            upstream,
            progress,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_slot_times_out_instead_of_hanging() {
        let slot = UpstreamSlot::new();
        assert!(slot.try_get().is_none());
        let waited = slot.wait(Duration::from_millis(50)).await;
        assert!(waited.is_none(), "пустой слот обязан отпустить по таймауту");
    }
}

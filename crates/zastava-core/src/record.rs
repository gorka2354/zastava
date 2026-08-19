//! Запись журнала вызовов (одна JSONL-строка на вызов).
//!
//! Core не знает про часы и файлы: временную метку и идентификатор события
//! поставляет вызывающий слой, сериализация — построчная (мульти-инстанс
//! пишет O_APPEND, межпроцессного батчинга нет — решение T6.5 ревью).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Вид записи журнала.
pub const KIND_CALL: &str = "call";
/// Вид записи журнала: событие самого гейтвея, не вызов инструмента.
pub const KIND_MARKER: &str = "marker";

fn default_kind() -> String {
    KIND_CALL.to_string()
}

/// Одна запись журнала.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRecord {
    /// Вид записи: `call` (вызов инструмента) или `marker` (событие гейтвея:
    /// старт, отключение аудита, ротация). Маркеры существуют, чтобы «аудит
    /// был выключен» и «вызовов не было» невозможно было спутать.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Момент вызова, RFC 3339 (UTC), проставляется proxy-слоем.
    pub ts: String,
    /// Короткий идентификатор события (для `zastava annotate`).
    pub id: String,
    /// Downstream-сервер.
    pub server: String,
    /// Инструмент (без префикса сервера).
    pub tool: String,
    /// Канонический поднабор аргументов (открыто; см. signature.rs).
    pub canonical_subset: BTreeMap<String, String>,
    /// Версия правил канонизации на момент записи.
    pub canon_version: u32,
    /// SHA-256 полных аргументов.
    pub args_hash: String,
    /// Вердикт политики: "allow" | "deny".
    pub decision: String,
    /// Был ли вердикт применён фактически (enforce) или только залогирован (warn).
    pub enforced: bool,
    /// Сработавшее правило, если было.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// Длительность downstream-вызова, мс (0, если вызов был заблокирован).
    pub duration_ms: u64,
    /// Размер сериализованного результата, байт (0, если заблокирован/ошибка).
    pub result_bytes: u64,
    /// Завершился ли вызов ошибкой (включая таймаут downstream).
    pub is_error: bool,
    /// Мы перестали ждать ответа (таймаут): downstream получил
    /// `notifications/cancelled`, но МОГ УСПЕТЬ выполнить побочный эффект.
    /// Такая запись не доказывает, что вызов не состоялся.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub abandoned: bool,
}

impl Default for CallRecord {
    fn default() -> Self {
        Self {
            kind: default_kind(),
            ts: String::new(),
            id: String::new(),
            server: String::new(),
            tool: String::new(),
            canonical_subset: BTreeMap::new(),
            canon_version: 0,
            args_hash: String::new(),
            decision: String::new(),
            enforced: false,
            matched_rule: None,
            duration_ms: 0,
            result_bytes: 0,
            is_error: false,
            abandoned: false,
        }
    }
}

impl CallRecord {
    /// Событие гейтвея (не вызов инструмента): старт, отключённый аудит,
    /// ротация журнала. `tool` несёт имя события, `matched_rule` — детали.
    /// Маркеры нужны, чтобы «аудит был выключен» и «вызовов не было»
    /// невозможно было спутать при чтении журнала.
    pub fn marker(ts: String, id: String, event: &str, detail: Option<String>) -> Self {
        Self {
            kind: KIND_MARKER.to_string(),
            ts,
            id,
            server: "zastava".to_string(),
            tool: event.to_string(),
            decision: "n/a".to_string(),
            matched_rule: detail,
            ..Default::default()
        }
    }

    /// Это запись о вызове инструмента (а не маркер события).
    pub fn is_call(&self) -> bool {
        self.kind == KIND_CALL
    }

    /// Сериализует запись в одну JSONL-строку (без завершающего `\n`).
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("CallRecord serialization cannot fail")
    }

    /// Разбирает одну строку журнала. Незнакомые строки вызывающий слой
    /// пропускает молча — журнал может писаться более новой версией.
    pub fn from_jsonl(line: &str) -> Option<Self> {
        serde_json::from_str(line).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CallRecord {
        CallRecord {
            kind: KIND_CALL.to_string(),
            ts: "2026-08-19T12:00:00Z".into(),
            id: "ev-0001".into(),
            server: "github".into(),
            tool: "create_issue".into(),
            canonical_subset: BTreeMap::new(),
            canon_version: 0,
            args_hash: "abc".into(),
            decision: "allow".into(),
            enforced: false,
            matched_rule: Some("github__*".into()),
            duration_ms: 42,
            result_bytes: 1024,
            is_error: false,
            abandoned: false,
        }
    }

    #[test]
    fn jsonl_roundtrip() {
        let record = sample();
        let line = record.to_jsonl();
        assert!(!line.contains('\n'), "запись обязана быть однострочной");
        assert_eq!(CallRecord::from_jsonl(&line), Some(record));
    }

    #[test]
    fn legacy_line_without_kind_is_read_as_call() {
        let mut line = sample().to_jsonl();
        line = line.replace("\"kind\":\"call\",", "");
        let parsed = CallRecord::from_jsonl(&line).expect("старые записи читаются");
        assert!(parsed.is_call());
    }

    #[test]
    fn marker_is_not_a_call() {
        let marker = CallRecord::marker(
            "t".into(),
            "id".into(),
            "audit_disabled",
            Some("ZASTAVA_DISABLE=1".into()),
        );
        assert!(!marker.is_call());
        let round = CallRecord::from_jsonl(&marker.to_jsonl()).unwrap();
        assert_eq!(round.tool, "audit_disabled");
        assert!(!round.is_call());
    }

    #[test]
    fn unknown_line_is_none_not_panic() {
        assert_eq!(CallRecord::from_jsonl("{\"какой-то\":\"мусор\"}"), None);
        assert_eq!(CallRecord::from_jsonl("не json"), None);
    }
}

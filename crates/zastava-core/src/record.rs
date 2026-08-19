//! Запись журнала вызовов (одна JSONL-строка на вызов).
//!
//! Core не знает про часы и файлы: временную метку и идентификатор события
//! поставляет вызывающий слой, сериализация — построчная (мульти-инстанс
//! пишет O_APPEND, межпроцессного батчинга нет — решение T6.5 ревью).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Одна запись журнала.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRecord {
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
}

impl CallRecord {
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
    fn unknown_line_is_none_not_panic() {
        assert_eq!(CallRecord::from_jsonl("{\"какой-то\":\"мусор\"}"), None);
        assert_eq!(CallRecord::from_jsonl("не json"), None);
    }
}

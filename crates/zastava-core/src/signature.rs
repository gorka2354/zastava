//! Сигнатуры вызовов и стабильный хэш аргументов.
//!
//! Формат лога (решение T2 ревью): `canonical_subset` пишется открыто (он по
//! построению низкокардинальный и без секретов), полные аргументы — только
//! хэшем. Сами правила канонизации живут в модуле [`crate::canon`].

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Версия правил канонизации. Пишется в каждую запись журнала: один и тот же
/// лог не должен давать противоположные сигнатуры после смены правил.
///
/// v0 — пустой subset (только tool-level).
/// v1 (M3) — whitelist ключей-идентификаторов с нормализацией значений.
pub const CANON_VERSION: u32 = 1;

/// SHA-256 канонической сериализации аргументов (hex). Стабилен относительно
/// порядка ключей: объекты сериализуются с сортировкой ключей на всех уровнях.
pub fn full_args_hash(args: &Map<String, Value>) -> String {
    let mut hasher = Sha256::new();
    let mut buf = String::new();
    write_canonical(&Value::Object(args.clone()), &mut buf);
    hasher.update(buf.as_bytes());
    hex(&hasher.finalize())
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            out.push('{');
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let mut first = true;
            for (key, val) in sorted {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            let mut first = true;
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(json: &str) -> Map<String, Value> {
        match serde_json::from_str(json).unwrap() {
            Value::Object(map) => map,
            _ => panic!("test json must be an object"),
        }
    }

    #[test]
    fn hash_is_stable_across_key_order() {
        let a = obj(r#"{"b": 1, "a": {"y": 2, "x": 3}}"#);
        let b = obj(r#"{"a": {"x": 3, "y": 2}, "b": 1}"#);
        assert_eq!(full_args_hash(&a), full_args_hash(&b));
    }

    #[test]
    fn hash_distinguishes_values() {
        let a = obj(r#"{"repo": "good"}"#);
        let b = obj(r#"{"repo": "evil"}"#);
        assert_ne!(full_args_hash(&a), full_args_hash(&b));
    }

    #[test]
    fn empty_args_hash_is_stable_constant() {
        // Фиксируем значение: смена = смена канонизации = бамп CANON_VERSION.
        assert_eq!(
            full_args_hash(&Map::new()),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn hash_covers_values_the_canonical_subset_drops() {
        // Журнал пишет открыто только canonical_subset; всё остальное живёт
        // в хэше. Значит, вызовы, различающиеся ТОЛЬКО скрытой частью, обязаны
        // различаться хэшем — иначе аудит не отличит их постфактум.
        let a = obj(r#"{"repo": "x", "body": "первый"}"#);
        let b = obj(r#"{"repo": "x", "body": "второй"}"#);
        assert_ne!(full_args_hash(&a), full_args_hash(&b));
    }
}

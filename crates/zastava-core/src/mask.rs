//! Маскировка секретов в аргументах, попадающих в журнал.
//!
//! Нужна ровно одной опции — `log.log_args`. По умолчанию аргументы в журнал
//! не пишутся вовсе (открыто идёт только `canonical_subset`), но человеку
//! иногда нужно видеть, ЧТО именно передавалось: при разборе инцидента, при
//! отладке правила, при сдаче работы заказчику. Опция для этого и есть — а
//! до M4 она писала всё как есть, включая токены.
//!
//! Три правила, и они намеренно перекрывают друг друга — секрет должен
//! попасться хотя бы одному:
//! 1. **По имени ключа.** `token`, `password`, `authorization` и родня: тут
//!    даже смотреть на значение не надо.
//! 2. **По виду значения.** Длинная бесструктурная строка из букв и цифр —
//!    типичный токен, как бы ни назывался ключ.
//! 3. **Учётные данные в URL.** `user:password@host` — самая чувствительная
//!    часть адреса, и по имени ключа она не ловится.
//!
//! Плюс потолок длины: журнал не должен раздуваться содержимым файлов, а
//! очень длинная строка почти наверняка данные, а не идентификатор.

use serde_json::{Map, Value};

/// Чем заменяется скрытое значение. Не пустая строка: читатель журнала
/// обязан отличать «значение скрыто» от «значения не было».
const MASKED: &str = "<masked>";

/// Потолок длины значения, попадающего в журнал.
const MAX_VALUE_LEN: usize = 2048;

/// Части имён ключей, при которых значение скрывается всегда.
const SECRET_KEY_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
    "cookie",
    "session",
    "bearer",
    "signature",
    "private",
    "apikey",
    "api_key",
];

/// Маскирует аргументы вызова для записи в журнал.
pub fn mask_args(args: &Map<String, Value>) -> Value {
    Value::Object(mask_object(args))
}

fn mask_object(args: &Map<String, Value>) -> Map<String, Value> {
    args.iter()
        .map(|(key, value)| (key.clone(), mask_value(key, value)))
        .collect()
}

fn mask_value(key: &str, value: &Value) -> Value {
    if is_secret_key(key) {
        return Value::String(MASKED.to_string());
    }
    match value {
        Value::String(raw) => Value::String(mask_string(raw)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                // Элементы массива наследуют имя ключа: `tokens: [...]`
                // скрывается целиком.
                .map(|item| mask_value(key, item))
                .collect(),
        ),
        Value::Object(inner) => Value::Object(mask_object(inner)),
        other => other.clone(),
    }
}

fn mask_string(raw: &str) -> String {
    if looks_like_secret(raw) {
        return MASKED.to_string();
    }
    let stripped = strip_url_credentials(raw);
    if stripped.chars().count() > MAX_VALUE_LEN {
        let head: String = stripped.chars().take(MAX_VALUE_LEN).collect();
        return format!("{head}…<обрезано>");
    }
    stripped
}

/// Скрывает ли имя ключа своё значение по определению.
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_PARTS.iter().any(|part| lower.contains(part))
}

/// Вырезает `user:password@` из адреса, оставляя сам адрес.
fn strip_url_credentials(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return raw.to_string();
    };
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_len);
    match authority.rsplit_once('@') {
        Some((_credentials, host)) => format!("{scheme}://{MASKED}@{host}{tail}"),
        None => raw.to_string(),
    }
}

/// Похоже ли значение на секрет: длинная бесструктурная строка из букв и
/// цифр без разделителей.
///
/// Живёт здесь, а не в [`crate::canon`], потому что нужна обеим сторонам:
/// канонизация решает, что писать открыто в `canonical_subset`, а маскировка —
/// что скрыть в полных аргументах. Правило должно быть ОДНО, иначе значение,
/// отвергнутое одним фильтром, спокойно пройдёт через другой.
pub fn looks_like_secret(value: &str) -> bool {
    const SECRET_MIN_LEN: usize = 20;
    let candidate = value.trim();
    if candidate.len() < SECRET_MIN_LEN {
        return false;
    }
    // Структурированное значение (путь, URL, фраза) — не секрет.
    if candidate.contains('/') || candidate.contains('\\') || candidate.contains(' ') {
        return false;
    }

    // Длинная сплошная hex-строка — ключ, сессия или хэш.
    let hexish = candidate
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '-')
        .count();
    if hexish == candidate.len()
        && candidate.chars().filter(char::is_ascii_hexdigit).count() >= SECRET_MIN_LEN
    {
        return true;
    }

    let distinct: std::collections::BTreeSet<char> = candidate.chars().collect();
    let alnum = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count();
    let has_digit = candidate.chars().any(|c| c.is_ascii_digit());
    let has_letter = candidate.chars().any(|c| c.is_ascii_alphabetic());
    // Требования смешанного регистра нет намеренно: `AKIAIOSFODNN7EXAMPLE` и
    // `ghp_...` в одном регистре — такие же секреты.
    alnum * 10 >= candidate.len() * 9 && distinct.len() >= 10 && has_digit && has_letter
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(json: &str) -> Map<String, Value> {
        match serde_json::from_str(json).unwrap() {
            Value::Object(map) => map,
            _ => panic!("нужен объект"),
        }
    }

    fn masked(json: &str) -> String {
        serde_json::to_string(&mask_args(&args(json))).unwrap()
    }

    #[test]
    fn secret_keys_are_masked_whatever_the_value_is() {
        let out = masked(r#"{"api_token":"short","Authorization":"Bearer x","PASSWORD":"123"}"#);
        assert!(!out.contains("short"), "{out}");
        assert!(!out.contains("Bearer x"), "{out}");
        assert!(!out.contains("123"), "{out}");
        assert_eq!(out.matches("<masked>").count(), 3, "{out}");
    }

    #[test]
    fn token_shaped_values_are_masked_under_any_key() {
        // Ключ ни о чём не говорит, а значение — типичный токен.
        let out = masked(r#"{"note":"ghp7Xk92LmQ4vTz8RaBn31YcWd05EfGh"}"#);
        assert!(!out.contains("ghp7Xk92"), "{out}");
    }

    #[test]
    fn ordinary_values_survive() {
        // Маскировка не имеет права съедать полезное: журнал с одними
        // `<masked>` бесполезен ровно так же, как журнал с токенами опасен.
        let out = masked(
            r#"{"repo":"gorka2354/zastava","path":"C:/work/zastava/src/main.rs","count":42,"ok":true}"#,
        );
        assert!(out.contains("gorka2354/zastava"), "{out}");
        assert!(out.contains("main.rs"), "{out}");
        assert!(out.contains("42"), "{out}");
        assert!(out.contains("true"), "{out}");
    }

    #[test]
    fn url_credentials_are_cut_but_the_address_stays() {
        let out = masked(r#"{"dsn":"postgres://svc:hunter2@db.internal:5432/prod"}"#);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("db.internal:5432/prod"), "адрес нужен: {out}");
    }

    #[test]
    fn nested_objects_and_arrays_are_masked_too() {
        let out = masked(r#"{"config":{"db":{"password":"p"}},"tokens":["a","b"]}"#);
        assert!(!out.contains("\"p\""), "вложенный секрет: {out}");
        assert!(!out.contains("\"a\""), "массив под секретным ключом: {out}");
    }

    #[test]
    fn very_long_values_are_truncated() {
        // Иначе `log_args` превращает журнал в свалку содержимого файлов.
        // Текст с пробелами — именно то, что маскировка по виду НЕ считает
        // секретом, то есть режет здесь один только потолок длины.
        let long = "lorem ipsum ".repeat(MAX_VALUE_LEN / 4);
        let out = masked(&format!(r#"{{"content":"{long}"}}"#));
        assert!(
            out.contains("lorem ipsum"),
            "текст не съеден целиком: усечение, а не маскировка"
        );
        assert!(out.contains("<обрезано>"), "длинное значение обрезается");
        assert!(out.len() < long.len(), "{}", out.len());
    }
}

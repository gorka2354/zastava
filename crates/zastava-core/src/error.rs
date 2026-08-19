//! Ошибки доменного ядра.

use thiserror::Error;

/// Ошибка разбора или валидации конфига. Политика проекта — fail-closed:
/// любой невалидный конфиг означает отказ старта, а не «работаем как получится».
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML не разобрался (синтаксис, неизвестные поля, неверные типы).
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),

    /// TOML разобрался, но содержимое не проходит доменную валидацию.
    /// Копим все проблемы разом, чтобы юзер чинил конфиг за один заход.
    #[error("config validation failed:\n{}", .0.iter().map(|p| format!("  - {p}")).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<String>),
}

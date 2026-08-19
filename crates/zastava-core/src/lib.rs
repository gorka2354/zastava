//! Доменное ядро Заставы: модель конфига, типы политик, сигнатуры вызовов.
//!
//! Крейт намеренно не делает IO (файлы, сеть, процессы) — всё это живёт в
//! `zastava-proxy` и `zastava-cli`. Благодаря этому домен тестируется чистыми
//! юнит-тестами без окружения.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;

pub use config::Config;
pub use error::ConfigError;

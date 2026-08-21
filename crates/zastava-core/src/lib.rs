//! Доменное ядро Заставы: модель конфига, политики, сигнатуры, журнал, learn.
//!
//! Крейт намеренно не делает IO (файлы, сеть, процессы, часы) — всё это живёт
//! в `zastava-proxy` и `zastava-cli`. Благодаря этому домен тестируется
//! чистыми юнит-тестами без окружения.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canon;
pub mod config;
pub mod error;
pub mod learn;
pub mod mask;
pub mod pathish;
pub mod policy;
pub mod record;
pub mod signature;
pub mod stats;

pub use canon::CanonRules;
pub use config::Config;
pub use error::ConfigError;
pub use policy::{Decision, PolicyEngine, Verdict};
pub use record::CallRecord;

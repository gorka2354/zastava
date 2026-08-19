//! Ошибки proxy-слоя.

use std::time::Duration;

use thiserror::Error;

/// Ошибки запуска и работы гейтвея.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Не удалось запустить процесс downstream-сервера.
    #[error("server '{server}': spawn failed: {message}")]
    Spawn {
        /// Имя сервера из конфига.
        server: String,
        /// Текст ошибки ОС.
        message: String,
    },

    /// Downstream не завершил initialize за отведённое время.
    #[error("server '{server}': initialize timed out after {timeout:?}")]
    InitializeTimeout {
        /// Имя сервера из конфига.
        server: String,
        /// Использованный таймаут.
        timeout: Duration,
    },

    /// Downstream ответил на initialize ошибкой.
    #[error("server '{server}': initialize failed: {message}")]
    Initialize {
        /// Имя сервера из конфига.
        server: String,
        /// Текст ошибки rmcp.
        message: String,
    },

    /// Ни один downstream не поднялся — гейтвею нечего проксировать.
    #[error("no downstream servers came up")]
    NoDownstreams,

    /// Не удалось поднять stdio-сервер для клиента.
    #[error("serve failed: {message}")]
    Serve {
        /// Текст ошибки rmcp.
        message: String,
    },
}

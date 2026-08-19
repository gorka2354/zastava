//! MCP-обвязка Заставы: rmcp server+client, спавн downstream'ов, роутинг.
//!
//! Наполняется в M1. Скелет проверен спайком (`spike/`): server-role +
//! client-role rmcp в одном процессе работают, включая протокольные
//! тонкости ревизии 2026-07-28 (ttlMs/cacheScope, resultType).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// M1: interceptor-chain поверх zastava_core::Config, spawn (Windows: cmd /c +
// Job Objects; Unix: setsid + process group), stderr-дренаж, O_APPEND-журнал.

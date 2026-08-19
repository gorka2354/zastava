//! JSONL-журнал вызовов.
//!
//! Решения ревью: hot path не ждёт диск (7A) — записи уходят в канал, пишет
//! отдельная блокирующая таска; каждая запись — ОДИН `write` строки в файл,
//! открытый в append-режиме (T6.5: два инстанса Заставы из двух сессий клиента
//! пишут в один файл без межпроцессного батчинга — построчный O_APPEND
//! атомарен на уровне строки). Сбой записи не блокирует вызовы (warning).
//! Ротация по размеру: > max → rename в `<path>.1` (перезаписывая старый).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use tokio::sync::mpsc;
use zastava_core::CallRecord;

/// Дефолтный потолок размера журнала до ротации (50 МБ).
pub const DEFAULT_MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;

/// Хендл журнала: дёшево клонируется, отправка не блокирует.
#[derive(Clone)]
pub struct LogHandle {
    tx: mpsc::UnboundedSender<CallRecord>,
}

impl LogHandle {
    /// Отправляет запись в журнал (fire-and-forget).
    pub fn write(&self, record: CallRecord) {
        if self.tx.send(record).is_err() {
            tracing::warn!("log writer is gone; call record dropped");
        }
    }
}

/// Запускает writer-таску журнала. Возвращает хендл для отправки записей.
pub fn start(path: PathBuf, max_bytes: u64) -> LogHandle {
    let (tx, mut rx) = mpsc::unbounded_channel::<CallRecord>();
    tokio::task::spawn_blocking(move || {
        while let Some(record) = rx.blocking_recv() {
            if let Err(e) = append_line(&path, max_bytes, &record.to_jsonl()) {
                tracing::warn!(error = %e, path = %path.display(), "log write failed (call not blocked)");
            }
        }
    });
    LogHandle { tx }
}

fn append_line(path: &Path, max_bytes: u64, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    rotate_if_needed(path, max_bytes)?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    // Одна строка — один write: атомарность на уровне строки для O_APPEND.
    file.write_all(format!("{line}\n").as_bytes())
}

/// Сколько поколений журнала храним (`.1` … `.N`).
///
/// Одного `.1` мало: заблокированный вызов пишет запись, не касаясь
/// downstream, то есть спам deny-вызовами стоит атакующему один JSON-RPC
/// фрейм и раньше двумя ротациями стирал всю историю (находка ревью M1).
pub const ROTATION_KEEP: u32 = 5;

fn rotate_if_needed(path: &Path, max_bytes: u64) -> std::io::Result<()> {
    let size = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(_) => return Ok(()),
    };
    if size < max_bytes {
        return Ok(());
    }
    let generation = |n: u32| path.with_extension(format!("jsonl.{n}"));

    // Сдвигаем поколения: самое старое уходит, остальные стареют на единицу.
    let _ = std::fs::remove_file(generation(ROTATION_KEEP));
    for n in (1..ROTATION_KEEP).rev() {
        let _ = std::fs::rename(generation(n), generation(n + 1));
    }
    // При гонке двух инстансов rename может проиграть — это не фатально:
    // проигравший просто продолжит писать в свежий файл.
    match std::fs::rename(path, generation(1)) {
        Ok(()) => {
            tracing::info!(to = %generation(1).display(), "log rotated");
            // Разрыв истории обязан быть виден в самом журнале.
            let marker = zastava_core::CallRecord::marker(
                crate::util::now_rfc3339(),
                crate::util::next_event_id(),
                "log_rotated",
                Some(format!(
                    "previous generation moved to {}",
                    generation(1).display()
                )),
            );
            let mut fresh = OpenOptions::new().create(true).append(true).open(path)?;
            fresh.write_all(format!("{}\n", marker.to_jsonl()).as_bytes())?;
        }
        Err(e) => tracing::warn!(error = %e, "log rotation failed"),
    }
    Ok(())
}

/// Читает журнал: незнакомые строки пропускаются молча (журнал мог писаться
/// другой версией — best effort по решению ревью).
pub fn read_records(path: &Path) -> std::io::Result<Vec<CallRecord>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content.lines().filter_map(CallRecord::from_jsonl).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> CallRecord {
        CallRecord {
            ts: "2026-08-19T12:00:00Z".into(),
            id: id.into(),
            server: "s".into(),
            tool: "t".into(),
            decision: "allow".into(),
            duration_ms: 1,
            result_bytes: 2,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn writes_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let handle = start(path.clone(), DEFAULT_MAX_LOG_BYTES);
        handle.write(record("a"));
        handle.write(record("b"));
        // Ждём writer-таску: канал разгружается быстро, но не мгновенно.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if read_records(&path).map(|r| r.len()).unwrap_or(0) == 2 {
                break;
            }
        }
        let records = read_records(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, "a");
    }

    #[test]
    fn reader_skips_unknown_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(
            &path,
            format!("мусор\n{}\n{{\"v\":2}}\n", record("ok").to_jsonl()),
        )
        .unwrap();
        let records = read_records(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "ok");
    }

    #[test]
    fn rotates_when_over_limit_and_marks_the_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(&path, "x".repeat(100)).unwrap();
        append_line(&path, 50, "{}").unwrap();
        assert!(
            path.with_extension("jsonl.1").exists(),
            "старый отротирован"
        );
        let fresh = std::fs::read_to_string(&path).unwrap();
        assert!(
            fresh.contains("log_rotated"),
            "разрыв истории должен быть виден маркером: {fresh}"
        );
        assert!(fresh.trim_end().ends_with("{}"), "и новая запись на месте");
    }

    #[test]
    fn keeps_several_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        for _ in 0..3 {
            std::fs::write(&path, "x".repeat(100)).unwrap();
            append_line(&path, 50, "{}").unwrap();
        }
        assert!(path.with_extension("jsonl.1").exists());
        assert!(
            path.with_extension("jsonl.2").exists(),
            "второе поколение не должно затираться первым"
        );
        assert!(path.with_extension("jsonl.3").exists());
    }
}

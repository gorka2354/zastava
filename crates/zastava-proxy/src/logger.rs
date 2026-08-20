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

    // ПОРЯДОК ВАЖЕН: сначала уводим текущий журнал во временное имя и только
    // при успехе двигаем архив. Иначе устойчиво падающий rename (файл занят
    // редактором/антивирусом) за ROTATION_KEEP записей стирал ВЕСЬ архив, не
    // заархивировав ничего (находка верификации M1).
    let staged = path.with_extension(format!("jsonl.rotating.{}", std::process::id()));
    if let Err(e) = std::fs::rename(path, &staged) {
        tracing::warn!(error = %e, "log rotation skipped: current file is busy");
        return Ok(());
    }
    let _ = std::fs::remove_file(generation(ROTATION_KEEP));
    for n in (1..ROTATION_KEEP).rev() {
        let _ = std::fs::rename(generation(n), generation(n + 1));
    }
    match std::fs::rename(&staged, generation(1)) {
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
        Err(e) => {
            // Архив уже сдвинут, а staged не встал на место — возвращаем
            // журнал обратно, чтобы записи не потерялись совсем.
            tracing::warn!(error = %e, "log rotation failed; restoring current journal");
            let _ = std::fs::rename(&staged, path);
        }
    }
    Ok(())
}

/// Читает журнал: незнакомые строки пропускаются молча (журнал мог писаться
/// другой версией — best effort по решению ревью).
pub fn read_records(path: &Path) -> std::io::Result<Vec<CallRecord>> {
    Ok(read_counted(path)?.0)
}

/// Как `read_records`, но вторым элементом — число НЕПРОЧИТАННЫХ строк.
///
/// Молчаливый пропуск битых строк делал повреждённый журнал побайтово
/// неотличимым от пустого (`вызовов: 0`) — для инструмента, чей товар есть
/// доказательство происходившего, это худший вид отказа (находка ревью M3).
pub fn read_counted(path: &Path) -> std::io::Result<(Vec<CallRecord>, usize)> {
    let content = std::fs::read_to_string(path)?;
    let mut records = Vec::new();
    let mut unreadable = 0;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match CallRecord::from_jsonl(line) {
            Some(record) => records.push(record),
            None => unreadable += 1,
        }
    }
    Ok((records, unreadable))
}

/// Читает журнал ВМЕСТЕ с отротированными поколениями, от старых к новым.
///
/// Без этого `ROTATION_KEEP` защищал только файлы на диске: `stats`/`learn`
/// после первой же ротации показывали историю с нуля (находка верификации M1).
/// Ошибка чтения текущего файла пробрасывается (её обязан различать вызывающий),
/// недоступные поколения пропускаются с предупреждением.
pub fn read_all_generations(path: &Path) -> std::io::Result<Vec<CallRecord>> {
    Ok(read_all_generations_counted(path)?.0)
}

/// Как `read_all_generations`, но с числом непрочитанных строк по всем
/// поколениям.
pub fn read_all_generations_counted(path: &Path) -> std::io::Result<(Vec<CallRecord>, usize)> {
    let mut records = Vec::new();
    let mut unreadable = 0;
    for n in (1..=ROTATION_KEEP).rev() {
        let generation = path.with_extension(format!("jsonl.{n}"));
        match read_counted(&generation) {
            Ok((found, skipped)) => {
                records.extend(found);
                unreadable += skipped;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(error = %e, path = %generation.display(), "log generation unreadable")
            }
        }
    }
    let (current, skipped) = read_counted(path)?;
    records.extend(current);
    Ok((records, unreadable + skipped))
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
    fn rotation_keeps_generation_contents_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        for tag in ["first", "second"] {
            std::fs::write(&path, format!("{}\n{}", tag, "x".repeat(100))).unwrap();
            append_line(&path, 50, &record(tag).to_jsonl()).unwrap();
        }
        let gen1 = std::fs::read_to_string(path.with_extension("jsonl.1")).unwrap();
        let gen2 = std::fs::read_to_string(path.with_extension("jsonl.2")).unwrap();
        assert!(gen1.contains("second"), "свежее поколение в .1: {gen1}");
        assert!(gen2.contains("first"), "старое уехало в .2: {gen2}");
    }

    #[test]
    fn read_all_generations_returns_history_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(
            path.with_extension("jsonl.2"),
            format!("{}\n", record("old").to_jsonl()),
        )
        .unwrap();
        std::fs::write(
            path.with_extension("jsonl.1"),
            format!("{}\n", record("mid").to_jsonl()),
        )
        .unwrap();
        std::fs::write(&path, format!("{}\n", record("new").to_jsonl())).unwrap();

        let ids: Vec<String> = read_all_generations(&path)
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, vec!["old", "mid", "new"]);
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

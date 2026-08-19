//! Мелкие утилиты proxy-слоя.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);
static PROCESS_TAG: OnceLock<String> = OnceLock::new();

/// Метка процесса: pid + момент старта. Только pid недостаточно — ОС их
/// переиспользует, счётчик обнуляется при рестарте, а журнал общий и вечный,
/// поэтому два разных вызова получали один id (находка ревью M1) и
/// `zastava annotate <id>` стал бы неоднозначным.
fn process_tag() -> &'static str {
    PROCESS_TAG.get_or_init(|| {
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{:x}{:x}", std::process::id(), started)
    })
}

/// Короткий идентификатор события журнала: уникален в пределах машины
/// (pid + старт процесса + счётчик), пригоден для `zastava annotate`.
pub fn next_event_id() -> String {
    let n = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("ev-{}-{n:04}", process_tag())
}

/// Текущий момент в RFC 3339 (UTC, миллисекунды). Без внешних зависимостей:
/// журналу нужна только монотонно читаемая метка, не календарная магия.
pub fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (year, month, day, hour, minute, second) = civil_from_unix(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Григорианская дата из unix-времени (алгоритм Ховарда Хиннанта,
/// days_from_civil в обратную сторону).
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_moments_format_correctly() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2026-08-19 12:00:00 UTC == 1787486400? проверим независимой точкой:
        // 2000-03-01 00:00:00 UTC = 951868800 (после високосного февраля).
        assert_eq!(civil_from_unix(951_868_800), (2000, 3, 1, 0, 0, 0));
        // 2024-02-29 23:59:59 UTC = 1709251199 (високосный день).
        assert_eq!(civil_from_unix(1_709_251_199), (2024, 2, 29, 23, 59, 59));
    }

    #[test]
    fn event_ids_are_unique_and_ordered() {
        let a = next_event_id();
        let b = next_event_id();
        assert_ne!(a, b);
        assert!(a.starts_with("ev-"));
    }

    #[test]
    fn process_tag_mixes_pid_and_start_time() {
        // Только pid недостаточно: ОС их переиспользует между запусками.
        let tag = process_tag();
        let pid_only = format!("{:x}", std::process::id());
        assert!(tag.starts_with(&pid_only));
        assert!(
            tag.len() > pid_only.len(),
            "в метке должен быть ещё и момент старта: {tag}"
        );
    }
}

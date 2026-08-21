//! Замеры M4: сколько Застава стоит в реальном сценарии.
//!
//! Меряется НЕ синтетика в одном процессе, а то, что видит клиент: настоящий
//! `zastava run`, настоящий дочерний MCP-сервер, настоящие stdio-каналы с
//! обеих сторон. Иначе цифра в README врала бы в приятную сторону —
//! in-process-канал быстрее пайпа на порядок, и весь «overhead» утонул бы в
//! разнице транспортов.
//!
//! Базовая линия честная: тот же клиент, тот же запрос, тот же дочерний
//! процесс — но напрямую, без Заставы. Разница двух распределений и есть цена.
//!
//! Три метрики, и две из них важнее третьей:
//! - **overhead p50/p99** — то, о чём спрашивают, но у прокси без сети он
//!   заведомо мал;
//! - **spawn-to-ready** — реальный риск: клиент ждёт эту паузу при КАЖДОМ
//!   старте, и она складывается из времени поднятия всех downstream'ов;
//! - **пауза reload** — второй реальный риск: смена политики на живом
//!   гейтвее не должна ощущаться как зависание.
//!
//! Запуск: `cargo bench -p zastava --bench latency` (нужен release-профиль,
//! `cargo bench` собирает его сам). Ставит цифры в stdout — их и переносим
//! в README, с указанием машины.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// Сколько вызовов меряем в каждом распределении.
const SAMPLES: usize = 2_000;
/// Прогрев: первые вызовы платят за ленивую инициализацию обеих сторон.
const WARMUP: usize = 200;
/// Сколько раз перезапускаем процесс для spawn-to-ready.
const SPAWN_RUNS: usize = 15;

fn main() {
    println!("== Застава: замеры задержек ==");
    println!(
        "платформа: {} {}, профиль: {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(debug_assertions) {
            "debug (ЦИФРЫ НЕ ДЛЯ README)"
        } else {
            "release"
        }
    );
    println!("сэмплов на распределение: {SAMPLES}\n");

    overhead();
    spawn_to_ready();
    reload_pause();
}

// ---------------------------------------------------------------- метрики

/// Цена посредничества: одинаковый вызов напрямую и через Заставу.
fn overhead() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "enforce");

    let mut direct = Conn::spawn_fixture();
    let direct_samples = measure(&mut direct, "echo");
    drop(direct);

    let mut through = Conn::spawn_zastava(&config);
    let through_samples = measure(&mut through, "alpha__echo");
    drop(through);

    let d = Stats::of(&direct_samples);
    let t = Stats::of(&through_samples);
    println!("-- overhead на вызов (tools/call, эхо-сервер) --");
    println!("  напрямую:      p50 {}  p99 {}", us(d.p50), us(d.p99));
    println!("  через Заставу: p50 {}  p99 {}", us(t.p50), us(t.p99));
    // Разница ПЕРЦЕНТИЛЕЙ, а не перцентиль разниц: попарно вычитать нечего —
    // это два независимых прогона, а не один вызов, измеренный дважды.
    println!(
        "  цена:          p50 {}  p99 {}\n",
        signed_us(t.p50, d.p50),
        signed_us(t.p99, d.p99)
    );
}

/// Пауза при старте клиента: от запуска процесса до первого ответа.
fn spawn_to_ready() {
    let dir = tempfile::tempdir().expect("tempdir");
    let one = write_config(dir.path(), "enforce");
    let dir4 = tempfile::tempdir().expect("tempdir");
    let four = write_config_n(dir4.path(), "enforce", 4);

    let mut bare = Vec::with_capacity(SPAWN_RUNS);
    let mut z1 = Vec::with_capacity(SPAWN_RUNS);
    let mut z1_hs = Vec::with_capacity(SPAWN_RUNS);
    let mut z4 = Vec::with_capacity(SPAWN_RUNS);
    let mut z4_hs = Vec::with_capacity(SPAWN_RUNS);
    for _ in 0..SPAWN_RUNS {
        let started = Instant::now();
        let mut conn = Conn::spawn_fixture();
        conn.request(99, "tools/list", "{}");
        bare.push(started.elapsed());
        drop(conn);

        for (config, totals, handshakes) in
            [(&one, &mut z1, &mut z1_hs), (&four, &mut z4, &mut z4_hs)]
        {
            let started = Instant::now();
            let mut conn = Conn::spawn_zastava(config);
            // Готовность = отвечает на tools/list, то есть downstream'ы
            // подняты, проинициализированы и их инструменты собраны. Ответ на
            // initialize приходит раньше, но по нему вызвать ещё нечего.
            conn.request(99, "tools/list", "{}");
            totals.push(started.elapsed());
            handshakes.push(conn.handshake);
            drop(conn);
        }
    }

    let b = Stats::of(&bare);
    let s1 = Stats::of(&z1);
    let s4 = Stats::of(&z4);
    println!("-- spawn-to-ready (процесс → первый tools/list) --");
    println!("  один голый сервер:   медиана {}", ms(b.p50));
    println!(
        "  Застава + 1 сервер:  медиана {}  максимум {}  (из них handshake {})",
        ms(s1.p50),
        ms(s1.max),
        ms(Stats::of(&z1_hs).p50)
    );
    println!(
        "  Застава + 4 сервера: медиана {}  максимум {}  (из них handshake {})",
        ms(s4.p50),
        ms(s4.max),
        ms(Stats::of(&z4_hs).p50)
    );
    println!("  цена посредника:     {}", signed_ms(s1.p50, b.p50));
    println!(
        "  4 сервера вместо 1:  {}
",
        signed_ms(s4.p50, s1.p50)
    );
}

/// Смена политики на живом гейтвее: видна ли она вызывающему.
fn reload_pause() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = write_config(dir.path(), "enforce");
    let mut conn = Conn::spawn_zastava(&config);

    for i in 0..WARMUP {
        conn.request(1000 + i as u64, "tools/call", CALL_ARGS_THROUGH);
    }
    let baseline = Stats::of(&measure(&mut conn, "alpha__echo"));

    // Переписываем конфиг и продолжаем звонить, пока reload не отработает.
    // Пауза, если она есть, попадёт в одну из этих задержек.
    write_config(dir.path(), "warn");
    let mut during = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut id = 50_000u64;
    while Instant::now() < deadline {
        id += 1;
        during.push(conn.request(id, "tools/call", CALL_ARGS_THROUGH));
    }
    let d = Stats::of(&during);

    println!("-- пауза при reload политики --");
    println!("  до reload:  p99 {}", us(baseline.p99));
    println!(
        "  во время:   p99 {}  максимум {} ({} вызовов за 3 с)",
        us(d.p99),
        us(d.max),
        during.len()
    );
    println!(
        "  худший вызов дороже обычного на {}\n",
        signed_us(d.max, baseline.p99)
    );
    drop(conn);
}

const CALL_ARGS_THROUGH: &str =
    r#"{"name":"alpha__echo","arguments":{"repo":"gorka2354/zastava"}}"#;

fn measure(conn: &mut Conn, tool: &str) -> Vec<Duration> {
    let params = format!(r#"{{"name":"{tool}","arguments":{{"repo":"gorka2354/zastava"}}}}"#);
    for i in 0..WARMUP {
        conn.request(10_000 + i as u64, "tools/call", &params);
    }
    (0..SAMPLES)
        .map(|i| conn.request(20_000 + i as u64, "tools/call", &params))
        .collect()
}

// ---------------------------------------------------------------- процессы

struct Conn {
    child: Child,
    stdout: BufReader<ChildStdout>,
    /// Сколько заняло от запуска процесса до ответа на `initialize`.
    /// Отдельно от `tools/list`, потому что это разные вещи: первое — старт
    /// самого гейтвея, второе — поднятие downstream'ов.
    handshake: Duration,
}

impl Conn {
    fn spawn_zastava(config: &Path) -> Self {
        Self::start(Command::new(env!("CARGO_BIN_EXE_zastava")).args([
            "--config",
            config.to_str().unwrap(),
            "run",
        ]))
    }

    fn spawn_fixture() -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zastava-test-echo"));
        command.env("ECHO_FIXTURE_NAME", "alpha");
        Self::start(&mut command)
    }

    fn start(command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let started = Instant::now();
        let mut conn = Self {
            child,
            stdout,
            handshake: Duration::ZERO,
        };
        conn.request(
            1,
            "initialize",
            r#"{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bench","version":"0"}}"#,
        );
        conn.handshake = started.elapsed();
        conn.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        conn
    }

    /// Отправляет запрос и ждёт ОТВЕТ НА НЕГО, пропуская уведомления.
    fn request(&mut self, id: u64, method: &str, params: &str) -> Duration {
        let line =
            format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#);
        let started = Instant::now();
        self.send(&line);
        let needle = format!("\"id\":{id}");
        loop {
            let mut buf = String::new();
            let read = self.stdout.read_line(&mut buf).expect("read");
            assert!(read > 0, "процесс закрыл stdout, не ответив на {method}");
            // Уведомления (progress, list_changed) идут тем же каналом и не
            // должны попадать в замер как «ответ».
            if buf.contains(&needle) {
                return started.elapsed();
            }
        }
    }

    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{line}").expect("write");
        stdin.flush().expect("flush");
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_config(dir: &Path, mode: &str) -> std::path::PathBuf {
    write_config_n(dir, mode, 1)
}

/// Конфиг с `servers` серверами. Больше одного нужно, чтобы проверить
/// заявленное: downstream'ы поднимаются параллельно, и четвёртый сервер не
/// добавляет к старту своё полное время.
fn write_config_n(dir: &Path, mode: &str, servers: usize) -> std::path::PathBuf {
    let path = dir.join("zastava.toml");
    let log = dir.join("calls.jsonl");
    let fixture = env!("CARGO_BIN_EXE_zastava-test-echo");
    let mut content = String::new();
    for i in 0..servers {
        // Первый всегда `alpha`: на него ссылаются замеры вызовов.
        let name = if i == 0 {
            "alpha".to_string()
        } else {
            format!("srv{i}")
        };
        content.push_str(&format!(
            "[servers.{name}]\ncommand = {fixture:?}\nenv = {{ ECHO_FIXTURE_NAME = \"{name}\" }}\n\n"
        ));
    }
    // Журнал ВСЕГДА внутрь временного каталога: бенч не имеет права
    // подмешивать свои вызовы в боевой аудит пользователя.
    content.push_str(&format!(
        "[log]\npath = {:?}\n\n[policy]\nmode = \"{mode}\"\ndefault = \"allow\"\n",
        log.to_string_lossy()
    ));
    std::fs::write(&path, content).expect("write config");
    path
}

// ---------------------------------------------------------------- цифры

struct Stats {
    p50: Duration,
    p99: Duration,
    max: Duration,
}

impl Stats {
    fn of(samples: &[Duration]) -> Self {
        assert!(!samples.is_empty(), "нечего считать");
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Self {
            p50: percentile(&sorted, 50),
            p99: percentile(&sorted, 99),
            max: *sorted.last().expect("непусто"),
        }
    }
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    let index = (sorted.len() * p) / 100;
    sorted[index.min(sorted.len() - 1)]
}

fn us(d: Duration) -> String {
    format!("{:.0} мкс", d.as_secs_f64() * 1e6)
}

fn ms(d: Duration) -> String {
    format!("{:.1} мс", d.as_secs_f64() * 1e3)
}

/// Разница двух замеров со знаком: она может выйти и отрицательной, и это не
/// повод её прятать — на таких величинах шум сравним с эффектом.
fn signed_us(a: Duration, b: Duration) -> String {
    let delta = a.as_secs_f64() * 1e6 - b.as_secs_f64() * 1e6;
    format!("{delta:+.0} мкс")
}

fn signed_ms(a: Duration, b: Duration) -> String {
    let delta = a.as_secs_f64() * 1e3 - b.as_secs_f64() * 1e3;
    format!("{delta:+.1} мс")
}

//! E2E-тесты реального бинаря `zastava run` с реальным дочерним процессом:
//! stdout-чистота (CI-тест из T6.12), EOF-уборка детей, deny-поток,
//! import из .claude.json.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;

fn fixture_path() -> &'static str {
    env!("CARGO_BIN_EXE_zastava-test-echo")
}

fn zastava_path() -> &'static str {
    env!("CARGO_BIN_EXE_zastava")
}

/// Пишет конфиг с одной фикстурой `alpha` и заданной секцией policy.
fn write_config(dir: &tempfile::TempDir, policy: &str, pid_file: Option<&Path>) -> PathBuf {
    let mut env_line = String::from("env = { ECHO_FIXTURE_NAME = \"alpha\"");
    if let Some(pid) = pid_file {
        env_line.push_str(&format!(
            ", ECHO_FIXTURE_PID_FILE = {:?}",
            pid.to_string_lossy()
        ));
    }
    env_line.push_str(" }");
    // Путь журнала задаётся ВСЕГДА и внутрь временного каталога.
    //
    // Без этого `zastava run` резолвит журнал по умолчанию — то есть в
    // БОЕВОЙ журнал пользователя, и каждый `cargo test` подмешивает туда
    // записи тестовых фикстур. Для продукта, чей товар — доказательство
    // происходившего, загрязнять пользовательский аудит прогоном тестов
    // недопустимо. Поймано на живом недельном эксперименте: в журнале
    // нашлись вызовы сервера `alpha`, которого у пользователя нет.
    //
    // Тест, которому журнал нужен для проверок, передаёт свой путь через
    // `policy` — тогда дефолт не добавляем, иначе выйдет дубль секции.
    let default_log = dir.path().join("calls.jsonl");
    let log_section = if policy.contains("[log]") {
        String::new()
    } else {
        format!("[log]\npath = {:?}\n\n", default_log.to_string_lossy())
    };
    let content = format!(
        "[servers.alpha]\ncommand = {:?}\n{env_line}\n\n{log_section}{policy}",
        fixture_path()
    );
    let path = dir.path().join("zastava.toml");
    std::fs::write(&path, content).unwrap();
    path
}

use std::path::{Path, PathBuf};

struct RunningZastava {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

fn start_run(config: &Path, extra: &[&str]) -> RunningZastava {
    let mut child = Command::new(zastava_path())
        .args(["--config", config.to_str().unwrap(), "run"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn zastava run");
    let stdout = BufReader::new(child.stdout.take().unwrap());
    RunningZastava { child, stdout }
}

impl RunningZastava {
    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn read_line(&mut self) -> String {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read stdout line");
        line
    }

    fn close_stdin(&mut self) {
        drop(self.child.stdin.take());
    }
}

impl Drop for RunningZastava {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .expect("tasklist");
        String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
    }
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

#[test]
fn stdout_is_pure_jsonrpc_and_tools_are_namespaced() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(&dir, "", None);
    let mut z = start_run(&config, &[]);

    z.send(INIT);
    let init_line = z.read_line();
    // stdout-дисциплина: каждая строка — валидный JSON-RPC, ни байта мусора.
    let parsed: serde_json::Value =
        serde_json::from_str(init_line.trim()).expect("stdout line must be pure JSON");
    assert_eq!(parsed["jsonrpc"], "2.0");

    z.send(INITIALIZED);
    z.send(LIST);
    let list_line = z.read_line();
    let listed: serde_json::Value = serde_json::from_str(list_line.trim()).unwrap();
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(names.contains(&"alpha__ping".to_string()), "{names:?}");
}

#[test]
fn eof_kills_downstream_children() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("child.pid");
    let config = write_config(&dir, "", Some(&pid_file));
    let mut z = start_run(&config, &[]);

    z.send(INIT);
    let _ = z.read_line();
    z.send(INITIALIZED);

    // Ждём pid-файл фикстуры.
    let mut child_pid = None;
    for _ in 0..100 {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                child_pid = Some(pid);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let child_pid = child_pid.expect("fixture must write its pid");
    assert!(pid_alive(child_pid), "фикстура должна быть жива");

    // EOF от клиента → гейтвей завершает работу и убирает детей.
    z.close_stdin();
    let _ = z.child.wait();

    let mut dead = false;
    for _ in 0..100 {
        if !pid_alive(child_pid) {
            dead = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        dead,
        "после EOF не должно оставаться сирот (pid {child_pid})"
    );
}

#[test]
fn enforce_denies_without_handing_the_model_a_bypass() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        "[policy]\nmode = \"enforce\"\ndefault = \"deny\"\n",
        None,
    );
    let mut z = start_run(&config, &[]);

    z.send(INIT);
    let _ = z.read_line();
    z.send(INITIALIZED);
    z.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"alpha__ping","arguments":{"message":"hi"}}}"#);
    let reply: serde_json::Value = serde_json::from_str(z.read_line().trim()).unwrap();
    assert_eq!(reply["result"]["isError"], true);
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("denied by zastava policy"), "{text}");
    assert!(
        !text.contains("zastava allow"),
        "команда обхода не должна попадать в контекст модели: {text}"
    );
}

#[test]
fn passthrough_flag_bypasses_enforce() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        "[policy]\nmode = \"enforce\"\ndefault = \"deny\"\n",
        None,
    );
    let mut z = start_run(&config, &["--passthrough"]);

    z.send(INIT);
    let _ = z.read_line();
    z.send(INITIALIZED);
    z.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"alpha__ping","arguments":{"message":"free"}}}"#);
    let reply: serde_json::Value = serde_json::from_str(z.read_line().trim()).unwrap();
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("pong: free"), "{text}");
}

#[test]
fn import_converts_claude_json_to_config() {
    let dir = tempfile::tempdir().unwrap();
    let claude_json = dir.path().join(".claude.json");
    std::fs::write(
        &claude_json,
        r#"{
          "mcpServers": {
            "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": { "TOKEN": "x" } },
            "notion": { "type": "http", "url": "https://mcp.notion.com/mcp" }
          }
        }"#,
    )
    .unwrap();
    let target = dir.path().join("zastava.toml");

    let output = Command::new(zastava_path())
        .args([
            "--config",
            target.to_str().unwrap(),
            "import",
            "--from",
            claude_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Импортировано серверов: 1"), "{stdout}");
    assert!(stdout.contains("пропущен: notion"), "{stdout}");

    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("[servers.github]"), "{written}");
    assert!(written.contains("TOKEN"), "{written}");

    // Повторный импорт без --force обязан отказать (не затираем молча).
    let second = Command::new(zastava_path())
        .args([
            "--config",
            target.to_str().unwrap(),
            "import",
            "--from",
            claude_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!second.status.success(), "без --force перезапись запрещена");
}

/// P1 ревью M1 (воспроизведён исполнением): ключ `env` из недоверенного
/// .claude.json склеивался в TOML сырым и мог закрыть inline-таблицу, дописав
/// собственную секцию [policy] — импорт молча выключал enforce.
#[test]
fn import_cannot_inject_a_policy_section() {
    let dir = tempfile::tempdir().unwrap();
    let claude_json = dir.path().join(".claude.json");
    let evil_key = "A = \"1\" }\n[policy]\nmode = \"warn\"\ndefault = \"allow\"\n[[policy.allow]]\nsig = \"victim__*\"\n#";
    let payload = serde_json::json!({
        "mcpServers": {
            "victim": { "command": "node", "args": ["server.js"], "env": { evil_key: "pwned" } }
        }
    });
    std::fs::write(&claude_json, payload.to_string()).unwrap();
    let target = dir.path().join("zastava.toml");

    let output = Command::new(zastava_path())
        .args([
            "--config",
            target.to_str().unwrap(),
            "import",
            "--from",
            claude_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let written = std::fs::read_to_string(&target).unwrap();
    // Секция политики не должна появиться ни при каком содержимом ключей.
    let policy_lines: Vec<&str> = written
        .lines()
        .filter(|l| l.trim_start().starts_with("[policy") || l.trim_start().starts_with("[[policy"))
        .collect();
    assert!(
        policy_lines.is_empty(),
        "импорт не имеет права порождать секции политики: {policy_lines:?}\n{written}"
    );

    // И сам конфиг обязан остаться на безопасных дефолтах.
    let check = Command::new(zastava_path())
        .args(["--config", target.to_str().unwrap(), "check"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&check.stdout);
    // Режим печатается ровно так, как его пишут в конфиг (`warn`, не
    // `Warn`): вывод `check` не должен расходиться с тем, что пользователь
    // пойдёт вставлять в файл.
    assert!(stdout.contains("mode=warn"), "{stdout}");
    assert!(stdout.contains("rules=0"), "{stdout}");
}

/// P2 ревью M1 (воспроизведён): sig подставлялась в TOML без валидации, и
/// `zastava allow` дописывал произвольные правила и подменял путь журнала.
#[test]
fn allow_rejects_injection_in_signature() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(&dir, "", None);
    let before = std::fs::read_to_string(&config).unwrap();

    let evil = "alpha__ping\"\n\n[[policy.allow]]\nsig = \"alpha__everything\"\n\n[log]\npath = \"C:/Temp/decoy.jsonl\"\n#";
    let output = Command::new(zastava_path())
        .args(["--config", config.to_str().unwrap(), "allow", evil])
        .output()
        .unwrap();
    assert!(!output.status.success(), "инъекция обязана отклоняться");

    let after = std::fs::read_to_string(&config).unwrap();
    assert_eq!(before, after, "конфиг не должен меняться при отказе");
}

/// Импорт двух имён, схлопывающихся в одно, обязан явно отказать, а не
/// молча потерять сервер (или упасть с «internal error»).
#[test]
fn import_reports_name_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let claude_json = dir.path().join(".claude.json");
    std::fs::write(
        &claude_json,
        r#"{"mcpServers": {"my.server": {"command": "a"}, "my-server": {"command": "b"}}}"#,
    )
    .unwrap();
    let target = dir.path().join("zastava.toml");
    let output = Command::new(zastava_path())
        .args([
            "--config",
            target.to_str().unwrap(),
            "import",
            "--from",
            claude_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("collision"),
        "{output:?}"
    );
}

/// Подчёркивание валидно в именах серверов — импорт не имеет права его
/// калечить (иначе едет весь неймспейс инструментов и клиентские правила).
#[test]
fn import_keeps_underscores_in_names() {
    let dir = tempfile::tempdir().unwrap();
    let claude_json = dir.path().join(".claude.json");
    std::fs::write(
        &claude_json,
        r#"{"mcpServers": {"claude_ai_Notion": {"command": "npx"}}}"#,
    )
    .unwrap();
    let target = dir.path().join("zastava.toml");
    Command::new(zastava_path())
        .args([
            "--config",
            target.to_str().unwrap(),
            "import",
            "--from",
            claude_json.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("claude_ai_Notion"), "{written}");
}

/// «Аудит отключён» и «вызовов не было» обязаны различаться в журнале.
#[test]
fn passthrough_leaves_an_audit_marker() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("calls.jsonl");
    let policy = format!(
        "[policy]\nmode = \"enforce\"\n\n[log]\npath = {:?}\n",
        log_path.to_string_lossy()
    );
    let config = write_config(&dir, &policy, None);
    {
        let mut z = start_run(&config, &["--passthrough"]);
        z.send(INIT);
        let _ = z.read_line();
        z.send(INITIALIZED);
        z.close_stdin();
        let _ = z.child.wait();
    }
    let journal = std::fs::read_to_string(&log_path).expect("журнал обязан существовать");
    assert!(
        journal.contains("policy_disabled"),
        "отключённый контроль обязан оставлять след: {journal}"
    );
}

/// Отсутствующий журнал ≠ пустая история.
#[test]
fn stats_distinguishes_missing_journal_from_empty_one() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nope.jsonl");
    let policy = format!("[log]\npath = {:?}\n", log_path.to_string_lossy());
    let config = write_config(&dir, &policy, None);

    let output = Command::new(zastava_path())
        .args(["--config", config.to_str().unwrap(), "stats"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ещё не создан"), "{stdout}");
}

#[test]
fn allow_appends_rule_and_check_sees_it() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(&dir, "# комментарий юзера — должен пережить allow\n", None);

    let output = Command::new(zastava_path())
        .args(["--config", config.to_str().unwrap(), "allow", "alpha__ping"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let written = std::fs::read_to_string(&config).unwrap();
    assert!(
        written.contains("# комментарий юзера"),
        "комментарии не трогаем"
    );
    assert!(written.contains("sig = \"alpha__ping\""));

    // Неизвестный сервер — отказ.
    let bad = Command::new(zastava_path())
        .args(["--config", config.to_str().unwrap(), "allow", "ghost__x"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}

/// Убивает процесс по pid. Нужен, чтобы смоделировать downstream, умерший
/// ПОСРЕДИ запроса — самый неприятный для аудита случай.
fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
    #[cfg(unix)]
    {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

#[test]
fn downstream_death_mid_request_is_audited_as_abandoned_not_failed() {
    // Запрос УЖЕ ушёл вниз, когда процесс умер: побочный эффект мог
    // состояться. До M2-full такой случай подставлял чужую ошибку и уезжал в
    // журнал как `failed: Unexpected response type` — то есть аудит утверждал,
    // что вызова не было, хотя он мог случиться.
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("child.pid");
    let log_path = dir.path().join("audit.jsonl");
    let policy = format!("[log]\npath = {:?}\n", log_path.to_string_lossy());
    let config = write_config(&dir, &policy, Some(&pid_file));
    let mut z = start_run(&config, &[]);

    z.send(INIT);
    let _ = z.read_line();
    z.send(INITIALIZED);
    z.send(LIST);
    let _ = z.read_line();

    let mut child_pid = None;
    for _ in 0..100 {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                child_pid = Some(pid);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let child_pid = child_pid.expect("фикстура должна записать свой pid");

    // Долгий вызов, который заведомо не успеет ответить.
    z.send(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"alpha__slow_ping","arguments":{"ms":30000}}}"#,
    );
    std::thread::sleep(Duration::from_millis(300));
    kill_pid(child_pid);

    // read_line блокируется, пока ответ не придёт: если гейтвей зависнет,
    // тест упрётся в общий таймаут, а не пройдёт молча.
    let answer = z.read_line();
    assert!(
        answer.contains("may still have taken effect"),
        "ответ обязан признать, что вызов мог состояться: {answer}"
    );
    assert!(
        !answer.contains("Unexpected response"),
        "чужая ошибка-затычка вместо честной причины: {answer}"
    );

    z.close_stdin();
    let _ = z.child.wait();

    let content = std::fs::read_to_string(&log_path).expect("журнал");
    let record = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|r| r["tool"] == "slow_ping")
        .expect("вызов обязан быть в аудите");
    assert_eq!(
        record["abandoned"], true,
        "аудит обязан пометить вызов как брошенный, а не как несостоявшийся: {record}"
    );
}

#[test]
fn the_audit_records_which_downstream_came_up_and_which_did_not() {
    // Версии протокола у клиента и у downstream'а могут РАЗОЙТИСЬ, и на этом
    // проект уже дважды ловил реальные баги (resultType, ttlMs). При разборе
    // инцидента первым делом спрашивают, какие версии там были — значит это
    // факт аудита, а не строчка в stderr.
    //
    // Упавший сервер тоже событие: без записи его инструменты просто молча
    // исчезают из выдачи, и человек видит «инструмента нет», а не «сервер не
    // поднялся».
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let policy = format!(
        "[servers.dead]\ncommand = \"no-such-binary-anywhere\"\n\n[log]\npath = {:?}\n",
        log_path.to_string_lossy()
    );
    let config = write_config(&dir, &policy, None);
    let mut z = start_run(&config, &[]);

    z.send(INIT);
    let _ = z.read_line();
    z.send(INITIALIZED);
    z.close_stdin();
    let _ = z.child.wait();

    let content = std::fs::read_to_string(&log_path).expect("журнал");
    let markers: Vec<(String, String)> = content
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|r| {
            (
                r["tool"].as_str().unwrap_or_default().to_string(),
                r["matched_rule"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let up = markers
        .iter()
        .find(|(tool, _)| tool == "downstream_up")
        .expect("поднявшийся сервер обязан быть в аудите");
    assert!(up.1.contains("alpha"), "{up:?}");
    assert!(
        up.1.contains("protocol 20"),
        "версия протокола обязана быть записана: {up:?}"
    );

    let failed = markers
        .iter()
        .find(|(tool, _)| tool == "downstream_failed")
        .expect("упавший сервер обязан быть в аудите");
    assert!(failed.1.contains("dead"), "{failed:?}");
}

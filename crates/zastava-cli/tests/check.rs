//! Интеграционные тесты `zastava check`: fail-closed поведение бинаря.

use assert_cmd::Command;
use predicates::prelude::*;

const VALID: &str = r#"
[servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[[policy.allow]]
sig = "github__*"
"#;

const INVALID_RULE: &str = r#"
[servers.github]
command = "npx"

[[policy.allow]]
sig = "unknown__*"
"#;

fn write_config(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("zastava.toml");
    std::fs::write(&path, content).expect("write config");
    (dir, path)
}

#[test]
fn check_accepts_valid_config() {
    let (_dir, path) = write_config(VALID);
    Command::cargo_bin("zastava")
        .unwrap()
        .args(["--config", path.to_str().unwrap(), "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Config OK"))
        .stdout(predicate::str::contains("github__*"));
}

#[test]
fn check_rejects_invalid_config_with_nonzero_exit() {
    let (_dir, path) = write_config(INVALID_RULE);
    Command::cargo_bin("zastava")
        .unwrap()
        .args(["--config", path.to_str().unwrap(), "check"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown server"));
}

#[test]
fn check_rejects_missing_file() {
    Command::cargo_bin("zastava")
        .unwrap()
        .args(["--config", "definitely/not/there.toml", "check"])
        .assert()
        .failure()
        // Пустая ошибка ОС на первом шаге — тупик; человек должен узнать,
        // с чего начать.
        .stderr(predicate::str::contains("конфига нет"))
        .stderr(predicate::str::contains("zastava import"));
}

/// Конфиг с журналом внутри временной директории.
fn write_config_with_log(dir: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    let log = dir.path().join("calls.jsonl");
    let config = dir.path().join("zastava.toml");
    let escaped = log.to_string_lossy().replace('\\', "\\\\");
    std::fs::write(&config, format!("{VALID}\n[log]\npath = \"{escaped}\"\n"))
        .expect("write config");
    (config, log)
}

#[test]
fn annotate_appends_a_note_for_a_real_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, log) = write_config_with_log(&dir);
    std::fs::write(
        &log,
        "{\"ts\":\"t\",\"id\":\"ev-1\",\"server\":\"github\",\"tool\":\"create_issue\",\"decision\":\"deny\"}\n",
    )
    .expect("seed journal");

    Command::cargo_bin("zastava")
        .unwrap()
        .args([
            "--config",
            config.to_str().unwrap(),
            "annotate",
            "ev-1",
            "спасло от записи в чужой репозиторий",
        ])
        .assert()
        .success();

    let written = std::fs::read_to_string(&log).expect("read journal");
    let last = written.lines().last().expect("annotation line");
    assert!(last.contains("annotation"), "{last}");
    assert!(last.contains("github__create_issue"), "{last}");
    // Исходная запись обязана уцелеть: журнал только дописывается.
    assert_eq!(written.lines().count(), 2, "{written}");
}

#[test]
fn annotate_refuses_unknown_event_instead_of_writing_into_the_void() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, log) = write_config_with_log(&dir);
    std::fs::write(
        &log,
        "{\"ts\":\"t\",\"id\":\"ev-1\",\"server\":\"a\",\"tool\":\"b\",\"decision\":\"allow\"}\n",
    )
    .expect("seed journal");

    Command::cargo_bin("zastava")
        .unwrap()
        .args([
            "--config",
            config.to_str().unwrap(),
            "annotate",
            "ev-404",
            "заметка",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("нет в журнале"));

    assert_eq!(
        std::fs::read_to_string(&log).expect("read").lines().count(),
        1,
        "неудачная аннотация не должна ничего писать"
    );
}

#[test]
fn annotate_rejects_an_event_id_that_would_break_the_journal_line() {
    // event_id приходит из командной строки: перевод строки в нём разорвал бы
    // JSONL-запись на две и подделал бы соседнюю строку аудита.
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, log) = write_config_with_log(&dir);
    std::fs::write(&log, "").expect("seed journal");

    Command::cargo_bin("zastava")
        .unwrap()
        .args([
            "--config",
            config.to_str().unwrap(),
            "annotate",
            "ev\n{\"kind\":\"call\",\"decision\":\"allow\"}",
            "заметка",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("не похож на идентификатор"));
}

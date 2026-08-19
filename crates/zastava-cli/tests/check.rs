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
        .stderr(predicate::str::contains("cannot read config"));
}

#[test]
fn run_is_honest_about_m1() {
    let (_dir, path) = write_config(VALID);
    Command::cargo_bin("zastava")
        .unwrap()
        .args(["--config", path.to_str().unwrap(), "run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("M1"));
}

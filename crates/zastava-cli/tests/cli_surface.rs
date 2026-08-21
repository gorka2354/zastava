//! Тесты ПОВЕРХНОСТИ CLI: того, что человек реально читает и по чему
//! принимает решения о своей защищённости.
//!
//! Существуют потому, что верификация M3 обнаружила системный пробел:
//! тестами было закрыто только ядро-библиотека, а весь вывод команд —
//! `check`, `stats`, `learn`, `events`, `allow` — не проверялся ничем.
//! Любую строку можно было удалить, и весь набор оставался зелёным. Между
//! тем именно эти строки и есть продукт: движок, который считает верно, но
//! рапортует неверно, хуже неработающего.

use assert_cmd::Command;
use predicates::prelude::*;

const NARROWED: &str = r#"
[servers.fs]
command = "node"

[policy]
mode = "enforce"
default = "deny"

[[policy.allow]]
sig = "fs__read_file"
args = { path = { prefix = "C:/work/zastava" } }
"#;

/// Кладёт конфиг и журнал во временный каталог.
fn workspace(config_body: &str, journal: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("calls.jsonl");
    let config = dir.path().join("zastava.toml");
    let escaped = log.to_string_lossy().replace('\\', "\\\\");
    std::fs::write(
        &config,
        format!("{config_body}\n[log]\npath = \"{escaped}\"\n"),
    )
    .expect("write config");
    if !journal.is_empty() {
        std::fs::write(&log, journal).expect("write journal");
    }
    (dir, config)
}

fn zastava(config: &std::path::Path, args: &[&str]) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("zastava").expect("binary");
    cmd.arg("--config").arg(config);
    cmd.args(args);
    cmd.assert()
}

/// Запись журнала текущего поколения канонизации.
fn call(id: &str, tool: &str, subset: &str, decision: &str, enforced: bool) -> String {
    format!(
        "{{\"kind\":\"call\",\"ts\":\"2026-08-20T10:00:00Z\",\"id\":\"{id}\",\"server\":\"fs\",\
         \"tool\":\"{tool}\",\"canonical_subset\":{subset},\"canon_version\":1,\
         \"args_hash\":\"h\",\"decision\":\"{decision}\",\"enforced\":{enforced},\
         \"duration_ms\":1,\"result_bytes\":0,\"is_error\":false}}\n"
    )
}

#[test]
fn check_says_out_loud_that_warn_blocks_nothing() {
    // Человек видит `default=deny` и считает, что защищён. В warn-режиме не
    // блокируется НИЧЕГО, и это должно быть написано словами.
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", "");
    zastava(&config, &["check"])
        .success()
        .stdout(predicate::str::contains("mode=warn"))
        .stdout(predicate::str::contains("НЕ блокируются"));
}

#[test]
fn check_warns_when_a_broad_rule_defeats_a_narrow_one() {
    let body = format!("{NARROWED}\n[[policy.allow]]\nsig = \"fs__*\"\n");
    let (_dir, config) = workspace(&body, "");
    zastava(&config, &["check"])
        .success()
        .stdout(predicate::str::contains("СУЖЕНИЕ НЕ ДЕЙСТВУЕТ"))
        .stdout(predicate::str::contains("fs__read_file"))
        .stdout(predicate::str::contains("fs__*"));
}

#[test]
fn allow_refuses_to_silently_kill_a_narrowing_but_obeys_force() {
    let (_dir, config) = workspace(NARROWED, "");
    let before = std::fs::read_to_string(&config).unwrap();

    zastava(&config, &["allow", "fs__*"])
        .failure()
        .stderr(predicate::str::contains("снимет аргументное сужение"));
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "отклонённая команда не имеет права править конфиг"
    );

    // Осознанное решение пользователя выполняется.
    zastava(&config, &["allow", "fs__*", "--force"]).success();
    assert!(std::fs::read_to_string(&config).unwrap().contains("fs__*"));
}

#[test]
fn stats_separates_verdicts_from_actual_blocks() {
    // «deny-вердиктов: 3» без второй строки читается как «меня прикрыли 3
    // раза», хотя в warn-режиме не прикрыли ни разу.
    let journal = format!(
        "{}{}{}",
        call("ev-1", "read_file", "{}", "deny", false),
        call("ev-2", "read_file", "{}", "deny", false),
        call("ev-3", "read_file", "{}", "allow", false),
    );
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", &journal);
    zastava(&config, &["stats"])
        .success()
        .stdout(predicate::str::contains("deny-вердиктов:      2"))
        .stdout(predicate::str::contains("из них заблокировано: 0"))
        .stdout(predicate::str::contains("не заблокировано НИ ОДНОГО"));
}

#[test]
fn stats_reports_a_corrupted_journal_instead_of_showing_it_as_empty() {
    let journal = format!(
        "{}не json\n{{\"oops\":1}}\n",
        call("ev-1", "t", "{}", "deny", true)
    );
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", &journal);
    zastava(&config, &["stats"])
        .success()
        .stdout(predicate::str::contains("НЕЧИТАЕМЫХ строк"))
        .stdout(predicate::str::contains("вызовов:            1"));
}

#[test]
fn events_shows_ids_that_annotate_accepts() {
    let journal = format!(
        "{}{}",
        call("ev-aaa", "read_file", "{}", "deny", true),
        call("ev-bbb", "write_file", "{}", "allow", true),
    );
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", &journal);
    zastava(&config, &["events"])
        .success()
        .stdout(predicate::str::contains("ev-aaa"))
        .stdout(predicate::str::contains("fs__read_file"))
        .stdout(predicate::str::contains("zastava annotate"));

    // Фильтр отказов оставляет только их.
    zastava(&config, &["events", "--denied"])
        .success()
        .stdout(predicate::str::contains("ev-aaa"))
        .stdout(predicate::str::contains("ev-bbb").not());

    // И показанный id действительно принимается annotate — иначе команда
    // существует, но пользоваться ею нечем.
    zastava(&config, &["annotate", "ev-aaa", "поймало чужой путь"]).success();
}

#[test]
fn events_show_what_the_call_asked_for() {
    // «Правило спасло или мешает» решается по аргументу, а не по имени
    // инструмента: список отказов без пути отвечает не на тот вопрос.
    let journal = call(
        "ev-ccc",
        "read_text_file",
        "{\"path\":\"/home/u/proj/.secrets/…\"}",
        "deny",
        true,
    );
    let (_dir, config) = workspace(
        "[servers.fs]
command = \"node\"
",
        &journal,
    );
    zastava(&config, &["events", "--denied"])
        .success()
        .stdout(predicate::str::contains("path=/home/u/proj/.secrets/…"));
}

#[test]
fn learn_prints_the_narrowing_and_warns_that_warn_mode_blocks_nothing() {
    let subset = "{\"path\":\"C:/work/zastava/src/…\"}";
    let journal = format!(
        "{}{}",
        call("ev-1", "write_file", subset, "deny", false),
        call("ev-2", "write_file", subset, "deny", false),
    );
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", &journal);
    zastava(&config, &["learn"])
        .success()
        .stdout(predicate::str::contains(
            "сужено: path начинается с C:/work/zastava/src",
        ))
        .stdout(predicate::str::contains("НИЧЕГО не блокируют"))
        // Матчер обязан жить внутри блока правила, иначе «вычеркни лишнее»
        // переклеивает его на соседнее правило.
        .stdout(predicate::str::contains("args = { path = { prefix ="))
        .stdout(predicate::str::contains("[policy.allow.args").not());
}

#[test]
fn learn_says_why_it_could_not_narrow_instead_of_going_quiet() {
    // Один вызов с обходом пути отключал сужение для инструмента навсегда и
    // молча (находка верификации M3).
    let journal = format!(
        "{}{}",
        call(
            "ev-1",
            "write_file",
            "{\"path\":\"C:/work/zastava/src/…\"}",
            "deny",
            false
        ),
        call(
            "ev-2",
            "write_file",
            "{\"path\":\"<rejected>\"}",
            "deny",
            false
        ),
    );
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", &journal);
    zastava(&config, &["learn"])
        .success()
        .stdout(predicate::str::contains("Сузить не удалось"))
        .stdout(predicate::str::contains("path"));
}

#[test]
fn learn_distinguishes_an_empty_journal_from_a_fully_covered_one() {
    let (_dir, config) = workspace("[servers.fs]\ncommand = \"node\"\n", "");
    std::fs::write(
        config.parent().unwrap().join("calls.jsonl"),
        "{\"kind\":\"marker\",\"ts\":\"t\",\"id\":\"m\",\"server\":\"zastava\",\"tool\":\"gateway_started\"}\n",
    )
    .unwrap();
    zastava(&config, &["learn"])
        .success()
        .stdout(predicate::str::contains("ещё нет вызовов"));
}

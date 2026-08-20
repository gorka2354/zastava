# zastava

[![CI](https://github.com/gorka2354/zastava/actions/workflows/ci.yml/badge.svg)](https://github.com/gorka2354/zastava/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/zastava.svg)](https://crates.io/crates/zastava)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![MSRV 1.85](https://img.shields.io/badge/MSRV-1.85-orange.svg)

**Work in progress (M3).** Застава — пограничный пункт досмотра для AI-агентов:
single-binary MCP-гейтвей, который агрегирует ваши MCP-серверы за одним endpoint
и добавляет то, чего не умеет клиентский `permissions.allow`.

Клиент умеет решать «инструмент можно или нельзя». Застава решает **на каких
аргументах**:

```toml
# «github можно, но только в мой репозиторий»
[[policy.allow]]
sig = "github__create_issue"
args = { repo = "gorka2354/zastava" }

# «файлы читать можно, но только в этом проекте»
[[policy.allow]]
sig = "fs__read_file"
args = { path = { prefix = "C:/work/zastava" } }
```

Что ещё:

- **аудит-лог** каждого вызова инструмента — с канонизованными аргументами
  (открыто пишутся только ключи-идентификаторы, всё остальное — хэшем);
- **`zastava learn`** — черновики правил из наблюдаемого поведения вместо
  ручного YAML, включая аргументные;
- **`zastava annotate`** — оценка срабатывания в момент события;
- **переносимость политик** между клиентами (Claude Code, Cursor, …).

Позиционирование выверено экспериментально — см. `spike/SPIKE.md`: контрольное
плечо показало, что tool-level тишину клиент даёт и без гейтвея, поэтому
Застава не притворяется «глушителем промптов».

## Как это работает

```
Claude Code ──stdio──> zastava ──┬──> github MCP
                                 ├──> filesystem MCP
                                 └──> qdrant MCP
                          │
                          ├── policy: аргументные матчеры (warn | enforce)
                          └── journal: JSONL, append-only
```

Инструменты выдаются клиенту с неймспейсом (`github__create_issue`), ресурсы
маршрутизируются по URI-владельцу, промпты — по префиксу имени.

## Цикл использования

Правила не пишутся с нуля — они вырастают из журнала:

```bash
cargo build
zastava import                  # перенести серверы из .claude.json
zastava check                   # валидация конфига и план политик
# в клиенте: {"mcpServers": {"zastava": {"command": "zastava", "args": ["run"]}}}

# поработали день в режиме warn (дефолт — только наблюдение)
zastava stats                   # что происходило
zastava learn                   # черновики правил, включая аргументные
zastava annotate ev-42 "этот deny спас от записи в чужой репозиторий"
# вычеркнули лишнее, вставили в zastava.toml, включили mode = "enforce"
```

`zastava allow <sig>` дописывает правило в конфиг, а работающий гейтвей
подхватывает его без перезапуска MCP-сессии.

## Что попадает в журнал

Аргументы вызова — это и содержимое файлов, и токены, поэтому целиком они не
пишутся никогда (пока явно не включить `log.log_args`). Открыто сохраняется
только `canonical_subset`: значения ключей-идентификаторов из whitelist
(`repo`, `path`, `collection`, …), с усечением путей до нескольких компонентов,
URL — до схемы и хоста, и с отказом от значений, похожих на секрет. Всё
остальное представлено `args_hash`.

## Статус

- [x] Spike: rmcp server+client в одном процессе, агрегация, неймспейсинг,
      живой Claude Code через прокси (`spike/`)
- [x] M0: workspace, `zastava check` (fail-closed конфиг), CI win+linux
- [x] M1: рабочий гейтвей — агрегация с неймспейсингом, policy-пайплайн
      (warn/enforce), аудит-журнал, живой reload правил, `stats` / `allow` /
      `learn` / `import` / `--passthrough`. Пройдено два независимых
      adversarial-ревью (3 P1 + 11 P2 закрыты с регрессионными тестами).
- [x] M2-lite: ресурсы и промпты проксируются и аудируются; возможности
      вычисляются из реальных downstream'ов
- [x] M3: аргументные матчеры (`exact` / `prefix` / `any_of`, `deny_extra_args`),
      канонизация журнала, `learn` с аргументными правилами, `annotate`,
      аудит ослабления политики на reload
- [x] Имя `zastava` закреплено на crates.io (заглушка 0.0.0; рабочий релиз — 0.1.0 на M4)
- [ ] M2-full (conformance) → M4 (release)

## Лицензия

MIT

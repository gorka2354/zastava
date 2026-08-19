# zastava

**Work in progress (M0).** Застава — пограничный пункт досмотра для AI-агентов:
single-binary MCP-гейтвей, который агрегирует ваши MCP-серверы за одним endpoint
и добавляет то, чего не умеет клиентский `permissions.allow`:

- **аргументные политики** — «github можно, но только repo X» (клиентские
  правила MCP-инструментов не матчат аргументы);
- **аудит-лог** каждого вызова инструмента;
- **`zastava learn`** — черновики правил из наблюдаемого поведения вместо
  ручного YAML;
- **переносимость политик** между клиентами (Claude Code, Cursor, …).

Позиционирование выверено экспериментально — см. `spike/SPIKE.md`: контрольное
плечо показало, что tool-level тишину клиент даёт и без гейтвея, поэтому
Застава не притворяется «глушителем промптов».

## Статус

- [x] Spike: rmcp server+client в одном процессе, агрегация, неймспейсинг,
      живой Claude Code через прокси (`spike/`)
- [x] M0: workspace, `zastava check` (fail-closed конфиг), CI win+linux
- [x] M1: рабочий гейтвей — агрегация с неймспейсингом, policy-пайплайн
      (warn/enforce), аудит-журнал, живой reload правил, `stats` / `allow` /
      `learn` / `import` / `--passthrough`. Пройдено два независимых
      adversarial-ревью (3 P1 + 11 P2 закрыты с регрессионными тестами).
- [ ] M2-lite → M3 (аргументные матчеры + learn) → M2-full → M4 (release)

## Попробовать

```bash
cargo build
zastava import                  # перенести серверы из .claude.json
zastava check                   # валидация конфига и план политик
# в клиенте: {"mcpServers": {"zastava": {"command": "zastava", "args": ["run"]}}}
zastava stats                   # что происходило
zastava learn                   # черновики правил из наблюдений
```

План: `inc/` (локально). Дизайн: `docs/designs/zastava-mcp-gateway.md`.

## Лицензия

MIT

# Baseline-счётчик permission-промптов Claude Code (spike Zastava).
# Вешается на Notification-хук с matcher "permission_prompt".
# Пишет одну JSONL-строку на каждый показанный промпт в ~/.zastava/baseline.jsonl.
$dir = Join-Path $env:USERPROFILE ".zastava"
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$stdin = [Console]::In.ReadToEnd()
$entry = @{ ts = (Get-Date).ToUniversalTime().ToString("o"); raw = $stdin } | ConvertTo-Json -Compress
Add-Content -Path (Join-Path $dir "baseline.jsonl") -Value $entry -Encoding utf8

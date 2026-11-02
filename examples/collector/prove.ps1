# Proves examples/collector/redact.yaml stops the Node demo's leak.
#   1. checks the config, 2. starts the Collector, 3. runs the demo through it, 4. stops the Collector.
# Usage (from the repo root):  .\examples\collector\prove.ps1 -Otelcol E:\Research\tools\otelcol\otelcol-contrib.exe
param([Parameter(Mandatory)][string]$Otelcol, [int]$Port = 4400)
$ErrorActionPreference = "Stop"
$config = Join-Path $PSScriptRoot "redact.yaml"
$env:TLC_PORT = "$Port"

& $Otelcol validate --config $config
if ($LASTEXITCODE -ne 0) { throw "Collector config is invalid" }

$col = Start-Process -FilePath $Otelcol -ArgumentList "--config", "`"$config`"" -PassThru -NoNewWindow `
    -RedirectStandardError (Join-Path $PSScriptRoot "otelcol.log")
try {
    Start-Sleep -Seconds 3
    uv run traceleakcheck run --port $Port --app-endpoint http://127.0.0.1:4318 --settle 3 -v -- node examples/node_agent/app.js
    $code = $LASTEXITCODE
} finally {
    Stop-Process -Id $col.Id -Force
}
Write-Host "traceleakcheck exit code: $code (0 = clean: the Collector removed the secret)"

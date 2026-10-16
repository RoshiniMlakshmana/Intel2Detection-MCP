param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$Database,
    [string]$ClaudeConfig = (Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'),
    [ValidateSet(30, 60)][int]$IntervalMinutes = 30,
    [string]$TaskName = 'Intel2Detection Collector'
)
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python not found: $Python" }
if (-not $Database) {
    if (-not (Test-Path -LiteralPath $ClaudeConfig)) { throw 'Claude config not found; pass -Database with the database shown by Claude polling_status.' }
    $Config = Get-Content -LiteralPath $ClaudeConfig -Raw | ConvertFrom-Json
    $Servers = @($Config.mcpServers.PSObject.Properties | Where-Object {
        ($_.Value.args -join ' ') -match 'threat_research|threat-research-mcp' -or $_.Name -match 'threat'
    })
    if ($Servers.Count -ne 1) { throw 'Cannot identify one threat-research server; pass -Database explicitly.' }
    $Database = $Servers[0].Value.env.THREAT_RESEARCH_DB
    if (-not $Database) {
        # Match the server default, while honoring inherited user configuration.
        $Database = $env:THREAT_RESEARCH_DB
        if (-not $Database) { $Database = '~/.threat-research/intel.sqlite3' }
    }
}
$Database = (& $Python -c 'import sys; from pathlib import Path; print(Path(sys.argv[1]).expanduser().resolve())' $Database)
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Database -PathType Leaf)) { throw 'Existing database not found; check the database path in Claude polling_status.' }
$Log = Join-Path (Split-Path $Database -Parent) 'collector-runs.jsonl'
$Existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Existing) {
    $Action = @($Existing.Actions)
    $Runner = Join-Path $RepoRoot 'scripts\run_collector.py'
    if ($Action.Count -ne 1 -or $Action[0].Execute -ne $Python -or
        -not $Action[0].Arguments.Contains('"' + $Database + '"') -or
        -not $Action[0].Arguments.Contains('"' + $Runner + '"')) {
        throw 'An existing task points elsewhere. Use a different -TaskName; it was not replaced.'
    }
    Enable-ScheduledTask -TaskName $TaskName | Out-Null
} else {
    & (Join-Path $RepoRoot 'scripts\install_collector_task.ps1') -RepoRoot $RepoRoot -Python $Python -Database $Database -IntervalMinutes $IntervalMinutes -TaskName $TaskName
}
# Use the registered task so collection can continue after this shell closes.
Start-ScheduledTask -TaskName $TaskName
Write-Output "Started $TaskName. Database: $Database"
Write-Output "Run log: $Log"
Write-Output 'The task repeats while you are logged in. Use Claude polling_status after the run completes; an empty or failed source must remain visible as degraded.'

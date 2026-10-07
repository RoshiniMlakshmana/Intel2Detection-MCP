param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$Python,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $Python) { $Python = Join-Path $RepoRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python not found: $Python" }
$Python = (Resolve-Path -LiteralPath $Python).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepoRoot ('offline-lab-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 1)) {
    throw 'Output directory must be new or empty; existing results will not be overwritten.'
}
$SavedEnvironment = @{}
foreach ($Key in @('THREAT_RESEARCH_DB', 'RULE_REPOSITORY_DIR', 'SMTP_HOST', 'ALERT_TO', 'DIGEST_TO', 'ALERT_RESEARCH', 'SPLUNK_TOKEN', 'GRAPH_TOKEN')) {
    $SavedEnvironment[$Key] = [Environment]::GetEnvironmentVariable($Key, 'Process')
}
$Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('intel2d-check-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Scratch | Out-Null
try {
    Push-Location $RepoRoot
    try {
        # Isolate inherited settings so tests never use the user's real DB/repository.
        $env:THREAT_RESEARCH_DB = Join-Path $Scratch 'test.sqlite3'
        foreach ($Key in @('RULE_REPOSITORY_DIR', 'SMTP_HOST', 'ALERT_TO', 'DIGEST_TO', 'ALERT_RESEARCH', 'SPLUNK_TOKEN', 'GRAPH_TOKEN')) {
            [Environment]::SetEnvironmentVariable($Key, $null, 'Process')
        }
        & $Python -m unittest discover -s tests
        if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed; see the failing test above.' }
        & $Python (Join-Path $RepoRoot 'scripts\smoke_mcp.py')
        if ($LASTEXITCODE -ne 0) { throw 'MCP smoke check failed.' }
        $env:RULE_REPOSITORY_DIR = Join-Path $OutputDirectory 'rule-repository'
        & $Python -m threat_research.cli demo-soc --output-directory $OutputDirectory
        if ($LASTEXITCODE -ne 0) { throw 'Synthetic lab failed.' }
        $Report = Get-Content -LiteralPath (Join-Path $OutputDirectory 'report.json') -Raw | ConvertFrom-Json
        if ($Report.drafts_tested -ne 3 -or $Report.measurement.sample_size -ne 12 -or
            $Report.measurement.counts.tp -ne 3 -or $Report.measurement.counts.fp -ne 2 -or
            $Report.measurement.counts.fn -ne 2 -or $Report.measurement.counts.tn -ne 5) {
            throw 'Synthetic replay differs from the documented baseline; inspect report.json.'
        }
        $Automatic = $Report.automatic_drafting
        if ($Automatic.status -ne 'passed' -or $Automatic.reports_tested -ne 5 -or
            $Automatic.automatic_drafts -ne 11 -or $Automatic.publisher_queries_translated -ne 7 -or
            $Automatic.checks_passed -ne 23 -or -not $Automatic.sigma_ids_unique -or -not $Automatic.dedup_passed) {
            throw 'Automatic report/KQL drafting checks failed; inspect automatic/report.json.'
        }
        Write-Output 'PASS: unit tests, MCP stdio, template replay, and automatic report/KQL drafting.'
        Write-Output 'Automatic drafting: 5 fictional reports, 11 server-written drafts, 7 KQL translations, 23 predicate checks; exclusions and IDs passed.'
        Write-Output "Lab results: $OutputDirectory"
        Write-Output 'Expected fixture counts: TP=3 FP=2 FN=2 TN=5. The misses and benign matches are intentional challenge cases.'
        Write-Output 'Rules remain drafts. Native SIEM validation was not run.'
    } finally {
        Pop-Location
    }
} finally {
    foreach ($Key in $SavedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Key, $SavedEnvironment[$Key], 'Process')
    }
    Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
}

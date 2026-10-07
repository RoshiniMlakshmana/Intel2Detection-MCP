param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$Python,
    [Parameter(Mandatory = $true)][string]$Database,
    [ValidateSet(30, 60)][int]$IntervalMinutes = 30,
    [string]$TaskName = 'Intel2Detection Collector'
)
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $Python) { $Python = Join-Path $RepoRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Python not found: $Python" }
$Python = (Resolve-Path -LiteralPath $Python).Path
$Database = [System.IO.Path]::GetFullPath($Database)
$Runner = Join-Path $RepoRoot 'scripts\run_collector.py'
$Log = Join-Path (Split-Path $Database -Parent) 'collector-runs.jsonl'
foreach ($Value in @($Python, $Runner, $Database, $Log)) {
    if ($Value.Contains('"')) { throw 'Paths cannot contain quotes' }
}
$Arguments = '"{0}" --database "{1}" --log "{2}" --interval-minutes {3}' -f $Runner, $Database, $Log, $IntervalMinutes
$Action = New-ScheduledTaskAction -Execute $Python -Argument $Arguments -WorkingDirectory $RepoRoot
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
# Register without -Force: an existing task is never silently replaced.
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description 'Collect independently of Claude; no notifications; JSONL run log.' | Out-Null
Write-Output "Installed $TaskName every $IntervalMinutes minutes while $User is logged in. Log: $Log"

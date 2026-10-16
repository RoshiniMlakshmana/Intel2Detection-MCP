param([string]$Output = '.\sysmon-export.xml', [ValidateRange(1,1000)][int]$MaxEvents = 200)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Output) { throw 'Choose a new output file; existing exports are not overwritten.' }
$Events = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } -MaxEvents $MaxEvents)
if (-not $Events.Count) { throw 'No Sysmon process events found; this script does not install Sysmon or create events.' }
$Content = '<Events>' + [Environment]::NewLine + (($Events | ForEach-Object { $_.ToXml() }) -join [Environment]::NewLine) + [Environment]::NewLine + '</Events>'
[System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Output), $Content, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Exported $($Events.Count) local process events to $Output. Truth labels are still required before measurement."

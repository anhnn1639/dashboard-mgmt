#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$EnrollmentToken,
    [string]$ServerCA = "",
    [string]$Python = "python.exe"
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:ProgramFiles "TramVanHanhAgent"
$DataDir = Join-Path $env:ProgramData "TramVanHanh"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
$InboxDir = Join-Path $DataDir "Inbox"
New-Item -ItemType Directory -Force -Path $InboxDir | Out-Null
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

& $Python -m venv (Join-Path $InstallDir "venv")
$AgentPython = Join-Path $InstallDir "venv\Scripts\python.exe"
& $AgentPython -m pip install --disable-pip-version-check --no-cache-dir -r (Join-Path $PSScriptRoot "requirements.txt")
Copy-Item -Force (Join-Path $PSScriptRoot "tram_agent.py") (Join-Path $InstallDir "tram_agent.py")

$EnrollArguments = @((Join-Path $InstallDir "tram_agent.py"), "--config", (Join-Path $DataDir "agent.json"), "enroll", "--server", $Server, "--token", $EnrollmentToken)
if ($ServerCA) { $EnrollArguments += @("--server-ca", $ServerCA) }
& $AgentPython @EnrollArguments

$Defender = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $Defender -or $Defender.Status -ne "Running") {
    Write-Warning "Microsoft Defender is not running. Secure file delivery will fail closed until an endpoint scanner is active."
}

$TaskName = "TramVanHanhAgent"
$Arguments = '"{0}" --config "{1}" --log-file "{2}" run' -f (Join-Path $InstallDir "tram_agent.py"), (Join-Path $DataDir "agent.json"), (Join-Path $DataDir "agent.log")
$Action = New-ScheduledTaskAction -Execute $AgentPython -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Agent installed and started. It will appear automatically under Windows in the dashboard." -ForegroundColor Green

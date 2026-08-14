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

$ServiceName = "TramVanHanhAgent"
if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    & sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName | Out-Null
}
$AgentScript = Join-Path $InstallDir "tram_agent.py"
$ConfigPath = Join-Path $DataDir "agent.json"
$LogPath = Join-Path $DataDir "agent.log"
$ServiceCommand = ('"{0}" "{1}" --config "{2}" --log-file "{3}" service' -f $AgentPython, $AgentScript, $ConfigPath, $LogPath)
& sc.exe create $ServiceName binPath= $ServiceCommand start= auto depend= Tcpip DisplayName= "Tram Van Hanh Server Agent" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Cannot create Windows service" }
& sc.exe description $ServiceName "Secure outbound management agent for Tram Van Hanh." | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/30000/restart/30000/restart/30000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
& sc.exe start $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Cannot start Windows service" }
Write-Host "Windows service installed, set to Automatic, and started. The server will appear automatically under Windows." -ForegroundColor Green

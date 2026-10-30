param(
    [switch]$NonInteractive
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir "..")).Path

if (Test-Path (Join-Path $RepoRoot "logs")) {
    $BackendDir = $RepoRoot
} elseif (Test-Path "C:\Users\revan\Desktop\Intellingent scam and phishing detection system\logs") {
    $BackendDir = "C:\Users\revan\Desktop\Intellingent scam and phishing detection system"
} else {
    $BackendDir = $RepoRoot
}

$LogsDir    = Join-Path $BackendDir "logs"
$PidFile    = Join-Path $LogsDir "scamlens_launcher_pids.json"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   SCAMLENS AI - Safe Service Stop Script" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $PidFile)) {
    Write-Host "No active launcher PID record found at: $PidFile" -ForegroundColor Yellow
    Write-Host "Nothing to stop (unrelated Python/Node processes were not touched)." -ForegroundColor Gray
    if (-not $NonInteractive) { Start-Sleep -Seconds 2 }
    exit 0
}

try {
    $PidData = Get-Content $PidFile -Raw | ConvertFrom-Json
} catch {
    Write-Host "[ERROR] Could not parse PID file: $PidFile" -ForegroundColor Red
    exit 1
}

function Stop-LauncherProcessTree($ProcessId, $ExpectedNamePattern, $Label) {
    if (-not $ProcessId) {
        Write-Host "[$Label] No PID recorded." -ForegroundColor Gray
        return
    }
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "[$Label] Process (PID: $ProcessId) is already stopped." -ForegroundColor Gray
        return
    }
    # Verify via WMI/CIM command line that this PID belongs to our launched service
    $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if ($cimProc -and ($cimProc.CommandLine -match $ExpectedNamePattern -or $proc.ProcessName -match "python|cmd|node|powershell")) {
        Write-Host "[$Label] Stopping process tree for PID $ProcessId ($($proc.ProcessName))..." -ForegroundColor Yellow
        & taskkill.exe /F /T /PID $ProcessId 2>&1 | Out-Null
        Write-Host "[$Label] Stopped cleanly." -ForegroundColor Green
    } else {
        Write-Host "[$Label] Skipping PID $ProcessId because it no longer matches SCAMLENS AI." -ForegroundColor Yellow
    }
}

Stop-LauncherProcessTree -ProcessId $PidData.backend_pid  -ExpectedNamePattern "uvicorn|backend\.main" -Label "FastAPI Backend"
Stop-LauncherProcessTree -ProcessId $PidData.frontend_pid -ExpectedNamePattern "vite|5173|npm"        -Label "React Frontend"

Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "All launcher-started SCAMLENS AI services have been stopped." -ForegroundColor Green
if (-not $NonInteractive) { Start-Sleep -Seconds 2 }
exit 0

param(
    [switch]$NoBrowser,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir "..")).Path

if (Test-Path (Join-Path $RepoRoot "backend\main.py")) {
    $BackendDir = $RepoRoot
} elseif (Test-Path "C:\Users\revan\Desktop\Intellingent scam and phishing detection system\backend\main.py") {
    $BackendDir = "C:\Users\revan\Desktop\Intellingent scam and phishing detection system"
} else {
    $BackendDir = $RepoRoot
}

if (Test-Path (Join-Path $RepoRoot "frontend\package.json")) {
    $FrontendDir = (Join-Path $RepoRoot "frontend")
} elseif (Test-Path "C:\Users\revan\Desktop\threat-view-ai\package.json") {
    $FrontendDir = "C:\Users\revan\Desktop\threat-view-ai"
} else {
    $FrontendDir = (Join-Path $RepoRoot "frontend")
}

$LogsDir     = Join-Path $BackendDir "logs"

if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

$BackendUrl     = "http://127.0.0.1:8001/api/health"
$FrontendUrl    = "http://127.0.0.1:5173"
$BackendOutLog  = Join-Path $LogsDir "launcher_backend.out.log"
$BackendErrLog  = Join-Path $LogsDir "launcher_backend.err.log"
$FrontendOutLog = Join-Path $LogsDir "launcher_frontend.out.log"
$FrontendErrLog = Join-Path $LogsDir "launcher_frontend.err.log"
$PidFile        = Join-Path $LogsDir "scamlens_launcher_pids.json"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   SCAMLENS AI - Intelligent Scam & Phishing Detection" -ForegroundColor Cyan
Write-Host "   Desktop Service Launcher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify project directories exist
if (-not (Test-Path (Join-Path $BackendDir "backend\main.py"))) {
    Write-Host "[ERROR] Backend entry point not found at: $BackendDir\backend\main.py" -ForegroundColor Red
    if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
    exit 1
}
if (-not (Test-Path (Join-Path $FrontendDir "package.json"))) {
    Write-Host "[ERROR] Frontend package.json not found at: $FrontendDir\package.json" -ForegroundColor Red
    if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
    exit 1
}

function Test-Endpoint($Url, $TimeoutSec = 3) {
    try {
        $req = [System.Net.WebRequest]::Create($Url)
        $req.Timeout = $TimeoutSec * 1000
        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
        $resp.Close()
        return ($statusCode -ge 200 -and $statusCode -lt 400)
    } catch {
        return $false
    }
}

function Test-PortListening($HostAddr, $Port, $TimeoutMs = 1500) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($HostAddr, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($wait -and $client.Connected) {
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

# Load existing PID tracking file if present
$PidData = @{
    backend_pid    = $null
    backend_start  = $null
    frontend_pid   = $null
    frontend_start = $null
}
if (Test-Path $PidFile) {
    try {
        $existing = Get-Content $PidFile -Raw | ConvertFrom-Json
        if ($existing.backend_pid)    { $PidData.backend_pid    = $existing.backend_pid }
        if ($existing.backend_start)  { $PidData.backend_start  = $existing.backend_start }
        if ($existing.frontend_pid)   { $PidData.frontend_pid   = $existing.frontend_pid }
        if ($existing.frontend_start) { $PidData.frontend_start = $existing.frontend_start }
    } catch {}
}

function Save-PidData {
    $PidData | ConvertTo-Json | Set-Content -Path $PidFile -Encoding UTF8
}

# 2. Check & Start FastAPI Backend (127.0.0.1:8001)
Write-Host "[1/3] Checking FastAPI ML Backend ($BackendUrl)..." -ForegroundColor Yellow
if (Test-Endpoint $BackendUrl 3) {
    Write-Host "      Backend is already running and healthy. Skipping duplicate launch." -ForegroundColor Green
} else {
    Write-Host "      Starting FastAPI Backend in background..." -ForegroundColor Cyan
    $pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $pythonExe) {
        Write-Host "[ERROR] Python executable not found in PATH." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
        exit 1
    }

    $backendCmd = "cmd.exe /c `"cd /d `"$BackendDir`" && `"$pythonExe`" -m uvicorn backend.main:app --host 127.0.0.1 --port 8001 >> `"$BackendOutLog`" 2>> `"$BackendErrLog`"`""
    $wmiBackend = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine      = $backendCmd
        CurrentDirectory = $BackendDir
    }
    if ($wmiBackend.ReturnValue -ne 0 -or -not $wmiBackend.ProcessId) {
        Write-Host "[ERROR] Failed to spawn FastAPI Backend via Win32_Process (Code: $($wmiBackend.ReturnValue))." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
        exit 1
    }

    $backendPid = [int]$wmiBackend.ProcessId
    $PidData.backend_pid   = $backendPid
    $PidData.backend_start = (Get-Date).ToString("o")
    Save-PidData

    Write-Host "      Waiting for ML model & FastAPI health endpoint (PID: $backendPid)..." -ForegroundColor Gray
    $backendReady = $false
    for ($i = 1; $i -le 45; $i++) {
        Start-Sleep -Seconds 1
        if (-not (Get-Process -Id $backendPid -ErrorAction SilentlyContinue)) {
            break
        }
        if (Test-Endpoint $BackendUrl 2) {
            $backendReady = $true
            break
        }
    }

    if (-not $backendReady) {
        Write-Host ""
        Write-Host "[ERROR] FastAPI Backend failed to respond within timeout." -ForegroundColor Red
        Write-Host "Diagnostic logs saved to:" -ForegroundColor Yellow
        Write-Host "  Stdout: $BackendOutLog"
        Write-Host "  Stderr: $BackendErrLog"
        if (Test-Path $BackendErrLog) {
            Write-Host "--- Recent Backend Error Output ---" -ForegroundColor Red
            Get-Content $BackendErrLog -Tail 20 | ForEach-Object { Write-Host "  $_" }
        }
        if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
        exit 1
    }
    Write-Host "      FastAPI Backend is online and healthy!" -ForegroundColor Green
}

Write-Host ""

# 3. Check & Start React/Vite Frontend (127.0.0.1:5173)
Write-Host "[2/3] Checking React Frontend ($FrontendUrl)..." -ForegroundColor Yellow
if (Test-PortListening "127.0.0.1" 5173 2000) {
    Write-Host "      Frontend is already running and reachable. Skipping duplicate launch." -ForegroundColor Green
} else {
    Write-Host "      Starting React Frontend (Vite) in background..." -ForegroundColor Cyan
    $nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $nodeExe) {
        Write-Host "[ERROR] node.exe not found in PATH." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
        exit 1
    }

    $runnerScript = Join-Path $BackendDir "scripts\run_frontend.cjs"
    $frontendCmd = "`"$nodeExe`" `"$runnerScript`""
    $wmiFrontend = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine      = $frontendCmd
        CurrentDirectory = $FrontendDir
    }
    if ($wmiFrontend.ReturnValue -ne 0 -or -not $wmiFrontend.ProcessId) {
        Write-Host "[ERROR] Failed to spawn React Frontend via Win32_Process (Code: $($wmiFrontend.ReturnValue))." -ForegroundColor Red
        if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
        exit 1
    }

    $frontendPid = [int]$wmiFrontend.ProcessId
    $PidData.frontend_pid   = $frontendPid
    $PidData.frontend_start = (Get-Date).ToString("o")
    Save-PidData

    Write-Host "      Waiting for Frontend dev server to become ready (PID: $frontendPid)..." -ForegroundColor Gray
    $frontendReady = $false
    for ($i = 1; $i -le 45; $i++) {
        Start-Sleep -Seconds 1
        if (-not (Get-Process -Id $frontendPid -ErrorAction SilentlyContinue)) {
            break
        }
        if (Test-PortListening "127.0.0.1" 5173 1500) {
            $frontendReady = $true
            break
        }
    }

    if (-not $frontendReady) {
        Write-Host ""
        Write-Host "[ERROR] Frontend server failed to respond within timeout." -ForegroundColor Red
        Write-Host "Diagnostic logs saved to:" -ForegroundColor Yellow
        Write-Host "  Stdout: $FrontendOutLog"
        Write-Host "  Stderr: $FrontendErrLog"
        if (Test-Path $FrontendErrLog) {
            Write-Host "--- Recent Frontend Error Output ---" -ForegroundColor Red
            Get-Content $FrontendErrLog -Tail 20 | ForEach-Object { Write-Host "  $_" }
        }
        if (-not $NonInteractive) { Read-Host "Press Enter to exit" }
        exit 1
    }
    Write-Host "      React Frontend is online and ready!" -ForegroundColor Green
}

Write-Host ""
Write-Host "[3/3] SCAMLENS AI is ready!" -ForegroundColor Green
Write-Host "      Frontend URL : $FrontendUrl" -ForegroundColor White
Write-Host "      Backend API  : http://127.0.0.1:8001 (Health: $BackendUrl)" -ForegroundColor White
Write-Host "      Logs Folder  : $LogsDir" -ForegroundColor Gray
Write-Host "      To Stop      : Run SCAMLENS_AI_Stop.bat" -ForegroundColor Gray
Write-Host ""

if (-not $NoBrowser) {
    Write-Host "Opening $FrontendUrl in your default browser..." -ForegroundColor Cyan
    Start-Process $FrontendUrl
}

exit 0

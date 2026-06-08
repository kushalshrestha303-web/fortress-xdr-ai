param(
  [int]$FrontendPort = 3000,
  [int]$BackendPort = 8090
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$backendDir = Join-Path $projectRoot "services/api"
$frontendDir = Join-Path $projectRoot "apps/command-center"
$venvPython = Join-Path $backendDir ".venv/Scripts/python.exe"
$frontendEnv = Join-Path $frontendDir ".env.local"

function Test-HttpOk {
  param([string]$Url)
  try {
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
    return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
  } catch {
    return $false
  }
}

function Test-PortListening {
  param([int]$Port)
  $line = netstat -ano | Select-String ":$Port\s+.*LISTENING"
  return [bool]$line
}

if (-not (Test-Path -LiteralPath $venvPython)) {
  Write-Host "Creating backend virtual environment..."
  Push-Location $backendDir
  python -m venv .venv
  & $venvPython -m pip install --upgrade pip
  & (Join-Path $backendDir ".venv/Scripts/pip.exe") install -r requirements.txt
  Pop-Location
}

if (-not (Test-Path -LiteralPath (Join-Path $backendDir ".env"))) {
  Copy-Item -LiteralPath (Join-Path $projectRoot ".env.example") -Destination (Join-Path $backendDir ".env")
}

Set-Content -LiteralPath $frontendEnv -Value "NEXT_PUBLIC_API_URL=/fortress-api`nBACKEND_API_URL=http://127.0.0.1:$BackendPort"

$backendHealth = "http://127.0.0.1:$BackendPort/api/v1/health"
if (Test-HttpOk $backendHealth) {
  Write-Host "Backend already running: $backendHealth"
} elseif (Test-PortListening $BackendPort) {
  Write-Host "Backend port $BackendPort is occupied, but health check failed. Stop that process or choose a different backend port."
} else {
  Write-Host "Starting backend on port $BackendPort..."
  Start-Process -FilePath $venvPython -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$BackendPort" -WorkingDirectory $backendDir -WindowStyle Hidden
}

if (Test-HttpOk "http://127.0.0.1:$FrontendPort") {
  Write-Host "Frontend already running: http://127.0.0.1:$FrontendPort"
} elseif (Test-PortListening $FrontendPort) {
  Write-Host "Frontend port $FrontendPort is occupied, but the app did not answer cleanly. Stop that process or choose a different frontend port."
} else {
  if (-not (Test-Path -LiteralPath (Join-Path $frontendDir "node_modules"))) {
    Write-Host "Installing frontend dependencies..."
    Push-Location $frontendDir
    npm.cmd install
    Pop-Location
  }
  Write-Host "Starting frontend on port $FrontendPort..."
  Start-Process -FilePath npm.cmd -ArgumentList "run", "dev", "--", "-p", "$FrontendPort" -WorkingDirectory $frontendDir -WindowStyle Hidden
}

Start-Sleep -Seconds 4

[pscustomobject]@{
  backend = if (Test-HttpOk $backendHealth) { "ok" } else { "not ready" }
  frontend = if (Test-HttpOk "http://127.0.0.1:$FrontendPort") { "ok" } else { "not ready" }
  app_url = "http://127.0.0.1:$FrontendPort"
  backend_health = $backendHealth
}

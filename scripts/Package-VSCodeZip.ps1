param(
  [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distDir = Join-Path $projectRoot "dist"
$stageRoot = Join-Path $distDir "nepal-fortress-one"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $distDir "nepal-fortress-one-vscode.zip"
}

$excludeDirectories = @(
  ".git",
  ".codex",
  "node_modules",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  "dist",
  "firewall-logs",
  ".mypy_cache",
  ".ruff_cache"
)

$excludeFiles = @(
  ".env",
  ".env.local",
  "*.log",
  "*.tmp",
  "*.pyc",
  "*.tsbuildinfo",
  "nepal-fortress-one-vscode.zip"
)

if (Test-Path -LiteralPath $stageRoot) {
  Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

robocopy $projectRoot $stageRoot /E /XD $excludeDirectories /XF $excludeFiles /NFL /NDL /NJH /NJS /NP | Out-Null
$robocopyExit = $LASTEXITCODE
if ($robocopyExit -ge 8) {
  throw "Robocopy failed with exit code $robocopyExit."
}

if (Test-Path -LiteralPath $OutputPath) {
  Remove-Item -LiteralPath $OutputPath -Force
}

Compress-Archive -Path $stageRoot -DestinationPath $OutputPath -CompressionLevel Optimal -Force

$zipInfo = Get-Item -LiteralPath $OutputPath
[pscustomobject]@{
  zip_path = $zipInfo.FullName
  size_mb = [math]::Round($zipInfo.Length / 1MB, 2)
  staged_from = $projectRoot
  excluded = ($excludeDirectories + $excludeFiles) -join ", "
}

param(
  [string]$ApiUrl = "http://127.0.0.1:8080/api/v1/ngfw/logs",
  [string]$TenantId = "local-windows-host",
  [ValidateSet("government", "bank", "hospital", "telecom", "enterprise", "critical-infrastructure")]
  [string]$Sector = "enterprise",
  [string]$SensorId = $env:COMPUTERNAME,
  [int]$Limit = 100,
  [switch]$ExternalOnly,
  [switch]$EstablishedOnly
)

$ErrorActionPreference = "Stop"

function Convert-PortToApplication {
  param([Nullable[int]]$Port)
  switch ($Port) {
    20 { return "ftp-data" }
    21 { return "ftp" }
    22 { return "ssh" }
    23 { return "telnet" }
    25 { return "smtp" }
    53 { return "dns" }
    80 { return "http" }
    110 { return "pop3" }
    143 { return "imap" }
    443 { return "https" }
    445 { return "smb" }
    587 { return "smtp-submission" }
    993 { return "imaps" }
    995 { return "pop3s" }
    1433 { return "mssql" }
    1521 { return "oracle" }
    3306 { return "mysql" }
    3389 { return "rdp" }
    5432 { return "postgresql" }
    6379 { return "redis" }
    9200 { return "opensearch" }
    default {
      if ($Port) { return "tcp-port-$Port" }
      return "tcp"
    }
  }
}

function Convert-RiskScore {
  param([Nullable[int]]$RemotePort, [string]$State)
  $riskyPorts = @(22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379, 9200)
  if ($RemotePort -in $riskyPorts) { return 78 }
  if ($State -eq "Established") { return 35 }
  if ($State -eq "Listen") { return 45 }
  return 20
}

function Get-ProcessNameSafe {
  param([int]$ProcessId)
  if (-not $ProcessId -or $ProcessId -le 0) { return "unknown-process" }
  try {
    return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName
  } catch {
    return "pid-$ProcessId"
  }
}

function Split-NetstatEndpoint {
  param([string]$Endpoint)
  if ([string]::IsNullOrWhiteSpace($Endpoint)) {
    return @{ address = "0.0.0.0"; port = 0 }
  }

  $lastColon = $Endpoint.LastIndexOf(":")
  if ($lastColon -lt 0) {
    return @{ address = $Endpoint; port = 0 }
  }

  $address = $Endpoint.Substring(0, $lastColon).Trim("[", "]")
  $portValue = $Endpoint.Substring($lastColon + 1)
  $port = 0
  [int]::TryParse($portValue, [ref]$port) | Out-Null

  return @{ address = $address; port = $port }
}

function Test-LoopbackAddress {
  param([string]$Address)
  return $Address -eq "127.0.0.1" -or $Address -eq "::1" -or $Address -eq "localhost"
}

function Get-LocalTcpConnections {
  try {
    return Get-NetTCPConnection |
      Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne "0.0.0.0" -and $_.RemoteAddress -ne "::" } |
      ForEach-Object {
        [pscustomobject]@{
          LocalAddress = [string]$_.LocalAddress
          LocalPort = [int]$_.LocalPort
          RemoteAddress = [string]$_.RemoteAddress
          RemotePort = [int]$_.RemotePort
          State = [string]$_.State
          OwningProcess = [int]$_.OwningProcess
        }
      }
  } catch {
    Write-Warning "Get-NetTCPConnection was blocked, falling back to netstat -ano."
  }

  $rows = netstat -ano -p tcp | Select-String -Pattern "^\s*TCP\s+"
  return $rows | ForEach-Object {
    $parts = $_.Line.Trim() -split "\s+"
    if ($parts.Count -lt 5) { return }

    $local = Split-NetstatEndpoint -Endpoint $parts[1]
    $remote = Split-NetstatEndpoint -Endpoint $parts[2]
    if ($remote.address -eq "0.0.0.0" -or $remote.address -eq "::" -or $remote.address -eq "*") { return }

    [pscustomobject]@{
      LocalAddress = [string]$local.address
      LocalPort = [int]$local.port
      RemoteAddress = [string]$remote.address
      RemotePort = [int]$remote.port
      State = [string]$parts[3]
      OwningProcess = [int]$parts[4]
    }
  }
}

$connections = Get-LocalTcpConnections | Select-Object -First $Limit
if ($ExternalOnly) {
  $connections = $connections | Where-Object {
    -not (Test-LoopbackAddress -Address $_.LocalAddress) -and -not (Test-LoopbackAddress -Address $_.RemoteAddress)
  }
}
if ($EstablishedOnly) {
  $connections = $connections | Where-Object { $_.State -eq "Established" }
}

$sent = 0
$failed = 0

foreach ($connection in $connections) {
  $processName = Get-ProcessNameSafe -ProcessId $connection.OwningProcess
  $application = Convert-PortToApplication -Port $connection.RemotePort
  $riskScore = Convert-RiskScore -RemotePort $connection.RemotePort -State ([string]$connection.State)
  $severity = if ($riskScore -ge 70) { "high" } elseif ($riskScore -ge 40) { "medium" } else { "info" }

  $payload = @{
    tenant_id = $TenantId
    sector = $Sector
    sensor_id = $SensorId
    src_ip = [string]$connection.LocalAddress
    dst_ip = [string]$connection.RemoteAddress
    src_port = [int]$connection.LocalPort
    dst_port = [int]$connection.RemotePort
    protocol = "TCP"
    application = $application
    action = "allowed"
    rule_id = "windows-local-connection"
    policy_name = "Windows Local TCP Telemetry"
    dpi = @{
      user_agent = "PowerShell Get-NetTCPConnection"
      process = $processName
    }
    ips = @{
      signature = "Local Windows TCP connection observed: $processName -> $application"
      severity = $severity
      blocked = $false
    }
    bytes_in = 0
    bytes_out = 0
    geo = @{
      src_country = "local"
      dst_country = "unknown"
    }
    threat_intel = @{
      source = "windows-local-network"
      state = [string]$connection.State
      owning_process = [string]$connection.OwningProcess
    }
  }

  try {
    Invoke-RestMethod -Method Post -Uri $ApiUrl -ContentType "application/json" -Body ($payload | ConvertTo-Json -Depth 8) | Out-Null
    $sent++
  } catch {
    $failed++
    Write-Warning "Failed to send local network telemetry: $($_.Exception.Message)"
  }
}

[pscustomobject]@{
  api_url = $ApiUrl
  sensor_id = $SensorId
  sent = $sent
  failed = $failed
}

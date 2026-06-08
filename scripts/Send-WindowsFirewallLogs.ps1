param(
  [string]$FirewallLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log",
  [string]$ApiUrl = "http://127.0.0.1:8080/api/v1/ngfw/logs",
  [string]$TenantId = "local-windows-host",
  [ValidateSet("government", "bank", "hospital", "telecom", "enterprise", "critical-infrastructure")]
  [string]$Sector = "enterprise",
  [string]$SensorId = $env:COMPUTERNAME,
  [int]$Tail = 50
)

$ErrorActionPreference = "Stop"

function Convert-Protocol {
  param([string]$Protocol)
  if ([string]::IsNullOrWhiteSpace($Protocol)) { return "UNKNOWN" }
  return $Protocol.ToUpperInvariant()
}

function Convert-Action {
  param([string]$Action)
  switch ($Action.ToUpperInvariant()) {
    "ALLOW" { return "allowed" }
    "DROP" { return "blocked" }
    default { return "alerted" }
  }
}

function Convert-Port {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "-") { return $null }
  $number = 0
  if ([int]::TryParse($Value, [ref]$number)) { return $number }
  return $null
}

function Get-RecordValue {
  param(
    [hashtable]$Record,
    [string]$Key,
    [string]$Default
  )
  if ($Record.ContainsKey($Key) -and -not [string]::IsNullOrWhiteSpace([string]$Record[$Key]) -and $Record[$Key] -ne "-") {
    return [string]$Record[$Key]
  }
  return $Default
}

if (-not (Test-Path -LiteralPath $FirewallLogPath)) {
  Write-Error "Windows Firewall log not found at '$FirewallLogPath'. Enable Windows Firewall logging first."
}

try {
  $fieldLine = Select-String -LiteralPath $FirewallLogPath -Pattern "^#Fields:" | Select-Object -Last 1
} catch [System.UnauthorizedAccessException] {
  Write-Error "Access denied reading '$FirewallLogPath'. Run this collector from an Administrator PowerShell, or grant your user read permission with: icacls `"$FirewallLogPath`" /grant `"$env:USERNAME`:R`""
} catch {
  if ($_.Exception.Message -match "Access.*denied") {
    Write-Error "Access denied reading '$FirewallLogPath'. Run this collector from an Administrator PowerShell, or grant your user read permission with: icacls `"$FirewallLogPath`" /grant `"$env:USERNAME`:R`""
  }
  Write-Error "Could not read '$FirewallLogPath': $($_.Exception.Message)"
}

if (-not $fieldLine) {
  Write-Error "Could not find #Fields header in '$FirewallLogPath'."
}

$fields = $fieldLine.Line.Replace("#Fields:", "").Trim().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
$entries = Get-Content -LiteralPath $FirewallLogPath -Tail $Tail | Where-Object {
  $_ -and -not $_.StartsWith("#")
}

$sent = 0
$failed = 0

foreach ($entry in $entries) {
  $values = $entry.Split(" ", [System.StringSplitOptions]::None)
  if ($values.Count -lt $fields.Count) { continue }

  $record = @{}
  for ($index = 0; $index -lt $fields.Count; $index++) {
    $record[$fields[$index]] = $values[$index]
  }

  $action = Convert-Action (Get-RecordValue -Record $record -Key "action" -Default "INFO")
  $protocol = Convert-Protocol (Get-RecordValue -Record $record -Key "protocol" -Default "UNKNOWN")
  $srcIp = Get-RecordValue -Record $record -Key "src-ip" -Default "0.0.0.0"
  $dstIp = Get-RecordValue -Record $record -Key "dst-ip" -Default "0.0.0.0"
  $srcPort = Convert-Port (Get-RecordValue -Record $record -Key "src-port" -Default "")
  $dstPort = Convert-Port (Get-RecordValue -Record $record -Key "dst-port" -Default "")
  $bytes = Convert-Port (Get-RecordValue -Record $record -Key "size" -Default "")
  $direction = Get-RecordValue -Record $record -Key "path" -Default "unknown"
  $tcpFlags = Get-RecordValue -Record $record -Key "tcpflags" -Default ""

  $signature = if ($action -eq "blocked") {
    "Windows Firewall blocked $protocol traffic"
  } else {
    "Windows Firewall observed $protocol traffic"
  }

  $severity = if ($action -eq "blocked") { "medium" } else { "info" }
  if ($dstPort -in @(22, 23, 3389, 445, 135, 139)) { $severity = "high" }

  $payload = @{
    tenant_id = $TenantId
    sector = $Sector
    sensor_id = $SensorId
    src_ip = $srcIp
    dst_ip = $dstIp
    src_port = $srcPort
    dst_port = $dstPort
    protocol = $protocol
    application = if ($dstPort) { "local-port-$dstPort" } else { "windows-firewall" }
    action = $action
    rule_id = "windows-firewall-local"
    policy_name = "Windows Defender Firewall"
    dpi = @{
      user_agent = "Windows Firewall pfirewall.log"
    }
    ips = @{
      signature = $signature
      severity = $severity
      blocked = ($action -eq "blocked")
    }
    bytes_in = if ($direction -eq "RECEIVE" -and $bytes) { $bytes } else { 0 }
    bytes_out = if ($direction -eq "SEND" -and $bytes) { $bytes } else { 0 }
    geo = @{
      src_country = "local"
      dst_country = "unknown"
    }
    threat_intel = @{
      source = "windows-firewall"
      direction = $direction
      tcp_flags = $tcpFlags
      raw = $entry
    }
  }

  try {
    Invoke-RestMethod -Method Post -Uri $ApiUrl -ContentType "application/json" -Body ($payload | ConvertTo-Json -Depth 8) | Out-Null
    $sent++
  } catch {
    $failed++
    Write-Warning "Failed to send firewall log: $($_.Exception.Message)"
  }
}

[pscustomobject]@{
  firewall_log_path = $FirewallLogPath
  api_url = $ApiUrl
  sent = $sent
  failed = $failed
}

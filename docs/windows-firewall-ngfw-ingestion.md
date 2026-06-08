# Windows Firewall Logs to Nepal Fortress ONE

This collector reads the local Windows Firewall `pfirewall.log`, maps entries to the existing NGFW API schema, and sends them to:

```text
http://127.0.0.1:8080/api/v1/ngfw/logs
```

Enable Windows Firewall logging in an elevated PowerShell:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384
```

Send the latest firewall entries:

```powershell
powershell -ExecutionPolicy Bypass -File ".\scripts\Send-WindowsFirewallLogs.ps1" -Tail 100
```

Then open Nepal Fortress ONE and go to **NGFW Logs**.

Notes:
- Run the command from the repository root.
- Reading `C:\Windows\System32\LogFiles\Firewall\pfirewall.log` may require Administrator permissions.
- The script does not expose secrets and uses the existing NGFW ingestion API.

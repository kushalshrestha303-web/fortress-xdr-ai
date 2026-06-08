# Troubleshooting

## Wazuh Not Running

```bash
sudo systemctl status wazuh-manager
sudo systemctl start wazuh-manager
sudo journalctl -u wazuh-manager -n 80 --no-pager
```

If the manager is down, the app may still connect to Indexer but no new alerts will appear.

## Suricata Not Running

```bash
sudo systemctl status suricata
sudo systemctl start suricata
sudo journalctl -u suricata -n 80 --no-pager
```

Confirm the network interface in the Suricata config matches your active interface.

## eve.json Missing

Check whether Suricata is writing JSON events:

```bash
sudo ls -l /var/log/suricata/eve.json
sudo tail -f /var/log/suricata/eve.json
```

If it is missing, enable `eve-log` in the Suricata YAML config and restart Suricata.

## Wazuh JSON Decoder Too Many Fields

If Wazuh logs mention too many JSON fields, reduce Suricata event verbosity or configure Wazuh to ingest only the required `eve.json` event types. Restart Wazuh after changing decoder or localfile settings.

## Suricata Alerts Not Showing In App

Verify the alert exists in Wazuh Indexer:

```bash
curl -k -u admin:your_real_password \
  "https://localhost:9200/wazuh-alerts-*/_search?q=rule.groups:suricata&pretty"
```

Then check:

- Backend `/alerts/suricata` returns data.
- Frontend is using the correct backend URL.
- The dashboard source filter is set to `All Alerts` or `Suricata`.
- The time range in Wazuh contains recent Suricata alerts.

## Indexer Authentication Failure

Test directly:

```bash
curl -k -u admin:your_real_password https://localhost:9200
```

If this fails, update `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD` in `.env`.

## Backend Cannot Connect To Wazuh

Check port reachability:

```bash
nc -vz 192.168.1.3 9200
curl -k -u admin:your_real_password https://192.168.1.3:9200
```

If Wazuh Indexer only listens on `127.0.0.1`, update its network binding or run the app on the same host.

## Frontend Cannot Connect To Backend

Confirm backend is running:

```bash
curl http://127.0.0.1:8000/health
```

If using a different backend port, set `VITE_API_BASE` before starting the frontend:

```bash
VITE_API_BASE=http://127.0.0.1:8001 npm run dev
```

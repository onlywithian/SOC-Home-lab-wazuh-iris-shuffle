# Wazuh to IRIS integration

Forwards Wazuh alerts at level 10 and above to IRIS as IRIS alerts.

| File | Purpose |
|---|---|
| `custom-iris` | Shell wrapper that runs the script with Wazuh's bundled Python |
| `custom-iris.py` | Builds the IRIS alert payload and POSTs it (3 retries, 10 s timeout) |
| `ossec-integration-snippet.xml` | The `<integration>` block for `ossec.conf` |
| `sample-alert.json` | Synthetic alert for testing without triggering an attack |

## Install

```bash
sudo cp custom-iris custom-iris.py /var/ossec/integrations/
sudo chmod 750 /var/ossec/integrations/custom-iris /var/ossec/integrations/custom-iris.py
sudo chown root:wazuh /var/ossec/integrations/custom-iris /var/ossec/integrations/custom-iris.py
# add the <integration> block from ossec-integration-snippet.xml to /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/integrations.log
```

If Wazuh runs in Docker, run these inside the manager container.

## Behaviour

- Severity mapping: level 15+ = Critical, 12-14 = High, 7-11 = Medium, 4-6 = Low, below 4 = Informational.
- MITRE technique and tactic IDs are added as IRIS tags.
- The API key is read from `ossec.conf`, never hard-coded.
- For lab self-signed certificates set `IRIS_VERIFY_TLS=false` (lab only) or point it to a CA bundle.
- Logs go to `/var/ossec/logs/integrations.log`.

## Troubleshooting

| Symptom | Check |
|---|---|
| No alert in IRIS | `tail /var/ossec/logs/integrations.log`; confirm the level threshold and the hook URL |
| HTTP 401 | API key wrong or expired: regenerate in IRIS under the user profile |
| HTTP 400 | Payload field rejected: compare severity, status and customer ids with your IRIS instance |
| TLS errors | Self-signed certificate: see `IRIS_VERIFY_TLS` |

# Shuffle playbook: IRIS case to VirusTotal enrichment

Trigger: IRIS webhook when a case status becomes **Investigating**.

| Node | App | What it does |
|---|---|---|
| 1. Webhook | Shuffle trigger | Receives the IRIS case event |
| 2. Extract hash | Shuffle tools | Pulls the file hash from the alert content |
| 3. VirusTotal lookup | VirusTotal | `GET /files/{hash}`, reads detection counts |
| 4. Condition | Shuffle tools | Continue only if detections > 10 |
| 5. Wazuh active response | HTTP / Wazuh | Authenticated request to the Wazuh API to run Active Response on the agent |
| 6. Notify | Email | Summary to the analyst (planned if not yet built) |

## Importing

1. Shuffle > Workflows > Import and select the JSON file.
2. Re-enter credentials: VirusTotal key, Wazuh API user and password.
3. Re-point the webhook URL in IRIS to the new trigger URL.

## Before you export

Strip API keys, passwords, auth tokens and public hostnames from the JSON. Search the file for
`key`, `token`, `password`, `Authorization` and your host IPs.

<!-- EDIT: list only the playbooks that actually exist and mark unfinished nodes as planned. -->


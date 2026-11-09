# Detections

Custom Wazuh rules used in this lab, with ATT&CK mapping and validation status.

| Rule ID | File | Level | What it detects | ATT&CK | Validated? | Evidence |
|---|---|---|---|---|---|---|
| 100002 | mimikatz-t1003.xml | 15 | Mimikatz process creation (by original file name) | T1003 OS Credential Dumping | Yes | screenshots/07-wazuh-mimikatz-alert-t1003.png |
| 100100 | ssh-bruteforce.xml | 5 | Single failed SSH password | T1110 | No | n/a |
| 100101 | ssh-bruteforce.xml | 12 | 5+ failures in 60 s from one source | T1110 | No | n/a |
| 100200 | suspicious-process.xml | 8 | Process launched from temp or downloads | T1204 | No | n/a |

## Design notes

- Level 10 and above is forwarded to IRIS, so only correlated or high-confidence rules sit at 10+.
- Detecting Mimikatz by original file name is easy to evade by renaming the binary,
  but `originalFileName` comes from the PE header so a simple rename does not defeat it.
  A stronger detection watches for access to `lsass.exe` (Sysmon Event ID 10). See the roadmap.
- Rule IDs 100000 and above are reserved for custom rules in Wazuh.

## How to deploy

1. Copy the XML into `/var/ossec/etc/rules/local_rules.xml` on the manager.
2. Check syntax: `sudo /var/ossec/bin/wazuh-logtest` (paste a sample event).
3. Restart: `sudo systemctl restart wazuh-manager`.
4. Confirm the rule loads: Wazuh dashboard > Management > Rules, search the rule ID.

## How to test

See `testing/mimikatz-simulation.md`. For the SSH rules, run repeated failed logins from the Kali VM
against a lab Linux host you own.

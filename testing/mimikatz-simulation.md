# Mimikatz simulation (T1003)

> **Lab only.** Run this only on a VM you own, on the isolated lab network. Never on production,
> shared or external systems. The Mimikatz binary is not included in this repository.

## Purpose

Validate that the pipeline detects OS credential dumping and carries the alert through IRIS and Shuffle.

## Prerequisites

- Windows 10 VM snapshot taken first (so you can roll back)
- Sysmon running and Event ID 1 reaching Wazuh
- Wazuh agent shown as **Active** in the dashboard
- Rule 100002 loaded (Management > Rules)
- IRIS and Shuffle reachable
- Windows Defender real-time protection will block Mimikatz: use a lab-only exclusion for the test
  folder and remove it afterwards

## Procedure

1. Note the current time (UTC) and open the Wazuh dashboard on the Security events view.
2. In PowerShell as Administrator, change to the folder holding your lab copy of the tool.
3. Start the tool and run `sekurlsa::logonpasswords`.
4. Watch Wazuh: filter with `rule.mitre.id: T1003`.
5. Open IRIS > Alerts and confirm the alert arrived.
6. Promote it to a case and set status to **Investigating**.
7. Open Shuffle > Executions and confirm the run and the VirusTotal result.

## Pass criteria

| Check | Pass |
|---|---|
| Wazuh alert | Level 10 or above with T1003 and Credential Access within 60 s |
| IRIS alert | Present within 60 s of the Wazuh alert |
| Shuffle | Execution successful, VirusTotal result logged |
| Other logs | Event stream continues, no timestamp gap |

## Measuring time to detect

In the Wazuh alert, compare the Sysmon event time (`data.win.system.systemTime`) with the alert
`timestamp`. Record the difference in `testing/test-cases.md`.

## Cleanup

Remove the lab exclusion, delete the tool, and revert to the snapshot.

## Evidence to capture
Screenshots 06 to 11 (see `testing/test-cases.md`)

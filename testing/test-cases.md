# Test cases

Environment: Windows 10 VM (Sysmon + Wazuh agent), Wazuh on Ubuntu VPS, IRIS and Shuffle on Ubuntu VPS.
Tester: Ian Obiero. Test dates: 15/04/2026 to 28/04/2026.

| ID | Level | Component | Test | Expected | Result | Evidence |
|---|---|---|---|---|---|---|
| TC-01 | Unit | Sysmon | Run commands on the VM and inspect Event Viewer | Sysmon events in Microsoft-Windows-Sysmon/Operational within 10 s | PASS | screenshots/03-sysmon-event-viewer.png |
| TC-02 | Unit | Wazuh agent | Check the Wazuh service on the VM | Service Running | PASS | screenshots/04-wazuh-agent-service-running.png |
| TC-03 | Integration | Wazuh manager | Agent appears Active, process events visible | Agent Active, 123+ process hits | PASS | screenshots/01-wazuh-agent-active.png, 02-wazuh-it-hygiene.png |
| TC-04 | Integration | IRIS | Trigger a level 10+ alert | Alert in IRIS within 60 s | PASS | screenshots/08-iris-alert-mimikatz.png |
| TC-05 | Integration | Shuffle | Set IRIS case to Investigating | Execution succeeds, VirusTotal lookup done | PASS | screenshots/09-shuffle-execution-virustotal.png |
| TC-06 | Validation | Detection | Run Mimikatz `sekurlsa::logonpasswords` | Alert level 10+ with T1003 within 60 s | PASS | screenshots/06-mimikatz-execution.png, 07-wazuh-mimikatz-alert-t1003.png |
| TC-07 | High-order | Active Response | Exceed VirusTotal threshold | netsh block rule created on the endpoint within 5 min | PENDING | screenshots/10-active-response-netsh-rule.png |
| TC-08 | High-order | Performance | Check log stream during the attack | No gap in event timestamps | PASS | screenshots/11-log-continuity.png |

## Metrics

| Metric | Value |
|---|---|
| Active agents | 1 |
| Time from Mimikatz execution to Wazuh alert | 21/04/2026 |
| Alerts in the 24 h window (critical / high / medium / low) | 1 / 1,941 / 3,396 / 39,879 |
| Query response time (24 h dashboard) | < 2 s |


testing/mimikatz-simulation.md
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

Screenshots 06 to 11 (see `testing/test-cases.md`). 

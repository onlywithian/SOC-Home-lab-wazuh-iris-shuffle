<img width="761" height="977" alt="SOC lab workflow" src="https://github.com/user-attachments/assets/4d3b33f2-c385-46dc-9236-acd084837340" />

The numbered arrows in the design diagram:

| # | Flow | Meaning |
|---|---|---|
| 1 | Send events | The Windows 10 client (Wazuh agent + Sysmon) sends events towards the Wazuh manager |
| 2 | Receive events | The Wazuh manager receives and decodes the events |
| 3 | Send alerts | Alerts leave the Wazuh manager for the automation layer |
| 4 | Enrich IOCs | The automation layer queries OSINT sources (VirusTotal) for indicators |
| 5 | Send alerts | Alerts are created in IRIS for case management |
| 6 | Send email | A notification email is produced for the analyst |
| 7 | Send and receive emails | The SOC analyst reads and answers the notification |
| 8 | Send response action | The analyst's decision is sent back as a response action |
| 9 | Perform responsive actions | Wazuh runs the response on the endpoint (Active Response) |

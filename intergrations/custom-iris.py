#!/usr/bin/env python3
"""
custom-iris.py: forward Wazuh alerts to IRIS as IRIS alerts.

Called by the Wazuh integrator (through the 'custom-iris' wrapper) as:
    custom-iris <alert_file> <api_key> <hook_url> [debug]

The API key and URL come from the <integration> block in ossec.conf, so nothing
secret lives in this file. Optional environment overrides:
    IRIS_VERIFY_TLS   "true" (default), "false", or a path to a CA bundle
    IRIS_CUSTOMER_ID  IRIS customer id (default 1)
"""
import json
import logging
import os
import sys
import time

import requests

LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_SECONDS = 10
MAX_RETRIES = 3

# IRIS ids. Verify these against your instance (Advanced > Alerts settings).
STATUS_NEW = 2
SEVERITY = {"critical": 6, "high": 5, "medium": 4, "low": 3, "info": 2}

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s custom-iris %(levelname)s: %(message)s",
)


def severity_from_level(level: int) -> int:
    """Map Wazuh rule level to an IRIS severity id."""
    if level >= 15:
        return SEVERITY["critical"]
    if level >= 12:
        return SEVERITY["high"]
    if level >= 7:
        return SEVERITY["medium"]
    if level >= 4:
        return SEVERITY["low"]
    return SEVERITY["info"]


def tls_verify():
    value = os.environ.get("IRIS_VERIFY_TLS", "true")
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value  # path to a CA bundle


def build_payload(alert: dict) -> dict:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    level = int(rule.get("level", 0))

    technique_ids = mitre.get("id", [])
    tactics = mitre.get("tactic", [])
    tags = ["wazuh"] + list(technique_ids) + [t.lower().replace(" ", "-") for t in tactics]

    description = (
        f"Rule {rule.get('id')} (level {level}): {rule.get('description', 'n/a')}\n"
        f"Agent: {agent.get('name', 'n/a')} ({agent.get('ip', 'n/a')})\n"
        f"MITRE: {', '.join(technique_ids) or 'n/a'} / {', '.join(tactics) or 'n/a'}"
    )

    return {
        "alert_title": rule.get("description", "Wazuh alert"),
        "alert_description": description,
        "alert_source": "Wazuh",
        "alert_source_ref": alert.get("id", ""),
        "alert_source_content": alert,
        "alert_source_event_time": alert.get("timestamp", "")[:19],
        "alert_severity_id": severity_from_level(level),
        "alert_status_id": STATUS_NEW,
        "alert_customer_id": int(os.environ.get("IRIS_CUSTOMER_ID", "1")),
        "alert_tags": ",".join(tags),
        "alert_context": {"agent": agent.get("name"), "rule_id": rule.get("id")},
    }


def send(payload: dict, api_key: str, hook_url: str) -> bool:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                hook_url,
                json=payload,
                headers=headers,
                timeout=TIMEOUT_SECONDS,
                verify=tls_verify(),
            )
            if resp.status_code in (200, 201):
                logging.info("alert %s forwarded (HTTP %s)", payload["alert_source_ref"], resp.status_code)
                return True
            logging.error("IRIS replied HTTP %s: %s", resp.status_code, resp.text[:300])
        except requests.RequestException as exc:
            logging.error("attempt %s/%s failed: %s", attempt, MAX_RETRIES, exc)
        time.sleep(2 * attempt)
    return False


def main() -> int:
    if len(sys.argv) < 4:
        logging.error("usage: custom-iris <alert_file> <api_key> <hook_url> [debug]")
        return 1

    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    if len(sys.argv) > 4 and sys.argv[4] == "debug":
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        with open(alert_file, encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logging.error("cannot read alert file %s: %s", alert_file, exc)
        return 1

    payload = build_payload(alert)
    return 0 if send(payload, api_key, hook_url) else 1


if __name__ == "__main__":
    sys.exit(main())

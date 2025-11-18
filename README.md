# 🛡️ Cloud Security Sandbox — Mini SOC for Learners

**Abstract.**  
This project aims to establish a real-time malware detection and response system within a secure sandbox environment, enhancing security practices and providing valuable training opportunities for SOC professionals.

---

## 🚀 Quick highlights (elevator)
- **Attacker:** Parrot / Kali VM — runs scans & exploit tools   
- **Telemetry:** Filebeat (logs) + Suricata (network) → OpenSearch/Elasticsearch  
- **Visualization:** Kibana or Grafana dashboards + alerting to Telegram/Slack  
- **Goal:** Teach detection, alerting, investigation, and basic remediation in a safe lab

---

## 📁 Repo structure (recommended)

```
cloud-soc-sandbox/
C:.
│   .gitignore
│   README.md
│
├───docs
│   │   offline-installation.md
│   │   SOC_Report.md
│   │
│   └───screenshots
│           1SOC_monitor.png
│           2SOC_alert.png
│           3Protection_history.png
│           4Defender_log.png
│           5SOC_log.png
│
├───logs
├───scripts
│   └───windows
│           monitor.ps1
│
└───tools
    ├───kali-debs
    │       libgcrypt20_1.11.2-2_amd64.deb
    │       libgpg-error0_1.55-2_amd64.deb
    │       libwireshark-data_4.4.9-1_all.deb
    │       libwireshark18_4.4.9-1_amd64.deb
    │       libwiretap15_4.4.9-1_amd64.deb
    │       libwsutil16_4.4.9-1_amd64.deb
    │       offline-tools-kali.iso
    │       offline-tools-new.iso
    │       offline-tools.iso
    │       Packages.gz
    │       suricata-8.0.2.tar.gz
    │       tshark_4.4.9-1_amd64.deb
    │       wireshark-common_4.4.9-1_amd64.deb
    │
    ├───sample-apps
    ├───scripts
    └───windows-portable


```

## ⚙️ Minimum viable environment (local)

Host OS: Ubuntu 22.04 / 24.04 (target VM)

Attacker: Parrot / Kali in VirtualBox / VMware

RAM: 12–16 GB recommended (8 GB minimum)

Disk: 40 GB free (SSD preferred)

Tools: Docker & docker-compose, Git, Python3


## ⚡ Quickstart — local dev (DVWA + Grafana example)

This is a minimal demo to get something visible quickly on your machine (Ubuntu target VM).

Clone repo and copy .env:

git clone https://github.com/<your-username>/cloud-soc-sandbox.git
cd cloud-soc-sandbox
cp .env.example .env   # edit values if needed


Minimal docker-compose.yml (example — place in repo root)

version: "3.8"
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "80:80"
    restart: always

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
    restart: always


Start stack:

docker compose up -d


Verify:

DVWA: http://localhost/ (or http://<vm-ip>/)

Grafana: http://localhost:3000 (admin/admin)

Note: This quickstart intentionally keeps the stack small. Full stack with OpenSearch/Suricata/Filebeat is shown later.

📥 Example Filebeat config (configs/filebeat.yml)

Minimal example for forwarding Apache logs to OpenSearch (adjust hosts):

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/apache2/*.log

output.elasticsearch:
  hosts: ["http://localhost:9200"]
  username: "elastic"
  password: "changeme"

🛡️ Example Suricata local rule (configs/suricata/local.rules)
# Detect simple SQLi attempts (UNION SELECT)
alert http any any -> $HOME_NET any (msg:"SQLi attempt - UNION SELECT"; flow:established,to_server; http_uri; content:"UNION"; nocase; content:"SELECT"; nocase; sid:1000001; rev:1;)

# Detect simple XSS pattern
alert http any any -> $HOME_NET any (msg:"XSS attempt - script tag"; flow:established,to_server; http_client_body; pcre:"/<script\b[^>]*>([\s\S]*?)<\/script>/i"; sid:1000002; rev:1;)


Load these into Suricata (/etc/suricata/rules/local.rules) and restart Suricata.

🔎 Example detection regex (Logstash / OpenSearch watcher or Kibana alert)


## 🧪 Attacker demo (safe, reproducible)

Place a demo attack script in scripts/demo/run-demo.sh:

#!/bin/bash
# small, safe demo: nmap + basic SQLi curl
TARGET=${1:-"127.0.0.1"}

echo "[*] Quick nmap service scan"
nmap -sS -Pn -p 80,443,3306 $TARGET -oN logs/nmap_quick.txt

echo "[*] Trigger simple SQLi test (DVWA)"
curl -s "http://$TARGET/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit&Submit=Submit" -d "id=' OR '1'='1" > logs/sqli_test.html


Run from attacker VM or host with caution. Keep small and short.

Capture logs & screenshots during the run for demo evidence.

## 📊 Dashboard ideas (Kibana / Grafana)

Overview panel: Total requests, Top 10 source IPs, Request rate (1m/5m)

Attack indicators: Count of events matching SQLi/XSS regex, alerts from Suricata

Auth panel: Failed login attempts by IP & username

Timeline: Attack timeline with request payload snippets (redact sensitive data)

## ✅ Demo script (what to show in your review)

Start monitoring stack (OpenSearch/Kibana or Grafana + Suricata).

From attacker: nmap -sS <target-ip> — show result.

Run the demo SQLi (curl script) or manual DVWA input.

In target: sudo tail -f /var/log/apache2/access.log — show malicious request.

In kibana/grafana: show a panel where the SQLi pattern is visible & alert fired.

Remediate quickly (block IP via ufw or fail2ban) and re-run to show mitigation.

## ⚠️ Safety & Ethics (must include)

Only test on lab-owned VMs and containers. Do not target external services, cloud provider infra, or other users.

If using cloud VMs, read provider penetration testing rules before running scans.

Use IP allowlists & temporary tunnels (ngrok with auth) if you must demo publicly.

Teardown and destroy public-facing instances after demo.

## 🛠 Troubleshooting

If you don’t see logs in OpenSearch: check Filebeat logs: sudo journalctl -u filebeat -f

Suricata not detecting traffic? Ensure Suricata runs on the interface seeing the traffic: sudo suricata -c /etc/suricata/suricata.yaml -i eth0

Docker container ports conflict? Stop conflicting services or change ports in docker-compose.yml.

## 🧭 Next steps & extensions

Add Wazuh for endpoint telemetry & pre-built detection rules.

Integrate MITRE ATT&CK mapping into dashboard events.

Add automated remediation (playbook) — e.g., when alert triggers, run a script to block IPs & notify Slack.

Replace minimal stack with a full ELK/OpenSearch cluster for more realistic volume.

## 📚 Useful references & learning (local resources)

DVWA: https://github.com/digininja/DVWA

OWASP Juice Shop: https://owasp.org/www-project-juice-shop/

Suricata rules & documentation: https://suricata.io/

Filebeat docs: https://www.elastic.co/guide/en/beats/filebeat/current/index.html

# 🛡️ Cloud Security Sandbox — Mini SOC for Learners

**_A hands-on Security Operations Center (SOC) lab for students & enthusiasts — simulate attacks, detect them, and practice response._**

---

## ▶️ Project Snapshot
- **Purpose:** Provide a safe, reproducible environment to learn offensive and defensive web security (DVWA, Juice Shop).  
- **Deliverable:** Docker-ready sandbox + detection rules + dashboards + demo scripts.  
- **Audience:** Beginners to intermediate students who want practical SOC experience.

---

## 📌 Highlights
- Run intentionally vulnerable apps (DVWA, Juice Shop) on an Ubuntu target VM.  
- Simulate attacks from an attacker VM (Parrot/Kali).  
- Collect logs (Filebeat / Docker logs) → store in OpenSearch/Elasticsearch.  
- Visualize & alert with Grafana / Kibana; notify via Telegram/Slack.

---

## 🧭 Tech Stack (concise)

| Layer | Tools / Examples |
|---|---|
| OS / VMs | Ubuntu 24.04 (target), Parrot/Kali (attacker) |
| Vulnerable Apps | DVWA, OWASP Juice Shop |
| Logging | Filebeat (or simple log-forwarder) |
| Storage / SIEM | OpenSearch / Elasticsearch |
| Visualization | Kibana, Grafana |
| Network IDS (optional) | Suricata / Snort |
| Scripting | Python, Bash |
| Containerization | Docker / docker-compose |
| Alerts | Telegram Bot API, Slack Webhooks |

---

## 🧪 Typical Lab Workflow

- Deploy target VM (Ubuntu) and attacker VM (Parrot).
- Run DVWA / Juice Shop on the target and verify login.
- Simulate attacks (nmap, sqlmap, simple XSS, small brute-force).
- Capture logs with Filebeat → OpenSearch.
- Visualize in Kibana/Grafana and configure alert rules.
- Respond (block IP / fail2ban / fix app) and re-test.

## 🔒 Safety & Ethics 

- All testing is performed only on lab-owned VMs. Do not target external machines.
- If exposing the lab publicly for a demo, use IP allowlists, basic auth, or a temporary tunnel (ngrok) and tear down the instance immediately after demo.


## 🐳 Docker Deployment

### DVWA Container

## 👤 Author

### Abinav Aaditya — Computer Science student & cybersecurity enthusiast
### GitHub: https://github.com/abhee-adhee


## 📝 License

This project is available under the MIT License. See LICENSE for details.

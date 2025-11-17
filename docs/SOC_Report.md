# SOC Defense Report

## 1. SOC Monitoring
**Screenshot:** docs/screenshots/1SOC_monitor.png  
SOC monitor was running, detecting file drops in real-time.

## 2. Malware Detection
**Screenshot:** docs/screenshots/2SOC_alert.png  
Fake malware download triggered Defender alert and SOC popup.

## 3. Protection History
**Screenshot:** docs/screenshots/3Protection_history.png  
Windows Defender quarantined fake_update.exe.

## 4. Event Viewer Logs
**Screenshot:** docs/screenshots/4Defender_log.png  
Operational log showing detection timestamp (for project documentation).

## 5. SOC Incident Log
**Screenshot:** docs/screenshots/5SOC_log.png  
SOC monitor logged the suspicious file and blocked the source IP.

## Conclusion
SOC successfully detected and recorded malware delivery, and Defender removed the threat. The workflow demonstrates **SOC detection → defense → incident logging**.

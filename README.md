# 🛡️ SOC Defense Demo — Real-Time Endpoint Monitoring & Threat Response

A lightweight security demonstration integrating Windows Defender with a custom SOC monitoring agent.

📌 Overview

This project demonstrates a basic endpoint security workflow by combining:

Windows Defender (native malware detection)

A custom PowerShell SOC Monitoring Agent

Real-time alerting, file quarantine, and logging

The system simulates a realistic chain:
Malicious file → Detection → Alert → Automatic removal → Logging → Evidence collection

This provides a simple but effective view of what happens inside a Security Operations Center (SOC) during an endpoint threat event.

## 🎯 Project Objectives

Show how modern endpoints detect and respond to malware.

Implement a lightweight SOC-style monitoring script.

Demonstrate real-time alerts and automated file response.

Capture system logs and evidence for analysis.

Provide a clean visual workflow using screenshots.

## 🧩 System Components
## 1️⃣ Windows Defender (Built-in Antivirus)

Used to detect malicious executables dropped into the system.
Defender provides:

Threat identification

Severity rating

Protection history

Event Viewer logs

This acts as the primary malware detection engine.

## 2️⃣ SOC Monitoring Agent (PowerShell Script)

A custom script that performs:

Continuous monitoring of the user’s Downloads folder

Detection of suspicious file extensions (.exe, .dll, .bat, .ps1, .vbs)

Popup alerts via GUI

Automatic removal (quarantine-style)

Logging of incidents to:

C:\sandbox_logs\incident_log.txt


This simulates how EDR tools (Endpoint Detection & Response) react in real systems.

## 👨‍💻 PowerShell Monitoring Script

Features implemented:
✔ Real-time directory watching
✔ Popup alert system
✔ Automatic file deletion
✔ Timestamped SOC logging
✔ Continues running until manually stopped

Core script excerpt:
```
Write-Host "[SOC] Immediate Monitoring Active" -ForegroundColor Cyan

$watchPath = "$env:USERPROFILE\Downloads"
$suspiciousExtensions = @(".exe", ".dll", ".bat", ".ps1", ".vbs")
$logFile = "C:\sandbox_logs\incident_log.txt"

# Ensure log folder exists
$logFolder = Split-Path $logFile
if (!(Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder | Out-Null }
if (!(Test-Path $logFile)) { New-Item -ItemType File -Path $logFile | Out-Null }

Add-Type -AssemblyName System.Windows.Forms

Write-Host "[SOC] Watching Downloads Folder..." -ForegroundColor Green
Write-Host "Press CTRL + C to Stop" -ForegroundColor Yellow

$knownFiles = @()

while ($true) {
    $currentFiles = Get-ChildItem -Path $watchPath -File -ErrorAction SilentlyContinue

    foreach ($file in $currentFiles) {
        if ($knownFiles -notcontains $file.FullName) {

            $knownFiles += $file.FullName
            $ext = $file.Extension.ToLower()

            if ($suspiciousExtensions -contains $ext) {

                [System.Windows.Forms.MessageBox]::Show(
                    "🚨 Suspicious file detected and removed:`n$file",
                    "SOC Alert",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )

                $log = "[$(Get-Date)] ALERT — Suspicious file detected & removed: $($file.FullName)"
                Add-Content $logFile $log

                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue

                Write-Host "🚨 ALERT Triggered & Removed: $($file.FullName)" -ForegroundColor Red
            }
            else {
                Write-Host "[SAFE] Downloaded: $($file.Name)" -ForegroundColor Green
            }
        }
    }

    Start-Sleep -Milliseconds 500
}
```
## 📸 Screenshots (Evidence of Workflow)

Stored in:

docs/screenshots/


Included images:

File	Description
1SOC_monitor.png	SOC script active and monitoring
2SOC_alert.png	Popup alert triggered
3Protection_history.png	Defender threat history
4Defender_log.png	System log from Event Viewer
5SOC_log.png	Logged SOC incident entry

These illustrate the full detection → response → logging chain.

## 🔄 End-to-End Attack Workflow
[Malicious File Dropped]
            ↓
[Windows Defender Detection]
            ↓
[Custom SOC Agent Identifies File]
            ↓
[Popup Alert + Auto Removal]
            ↓
[Incident Logged in SOC Log File]
            ↓
[Evidence Shown in Defender History + Event Viewer]


This is a simplified but realistic representation of endpoint defense.

📦 Folder Structure
project/
│
├── docs/
│   └── screenshots/
│       ├── 1SOC_monitor.png
│       ├── 2SOC_alert.png
│       ├── 3Protection_history.png
│       ├── 4Defender_log.png
│       └── 5SOC_log.png
│
├── SOC_Monitor.ps1
└── README.md

## 🔒 Limitations

This is a demo and not a full EDR product.
Limitations include:

Signature-based detection (file extension check only)

No behavioral analysis

Single-folder monitoring

Suitable only for educational use

## 🚀 Future Improvements

Potential enhancements:

Monitor multiple directories

Integrate webhook alerts (Telegram, Discord)

Add hash-based detection

Add behavioral anomaly detection

Visual dashboard (Grafana)

Convert script into a background Windows service

## 📚 Purpose

This project is meant to serve as a learning tool for understanding:

Malware detection

SOC alerting

Automated incident response

Windows Defender’s telemetry

Endpoint security fundamentals

It is simple, safe, and ideal for demonstrating how endpoint monitoring works.

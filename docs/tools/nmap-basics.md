# 🔍 Nmap - Network Scanning Basics

## What is Nmap?
Network Mapper - powerful network scanning and discovery tool

## Basic Commands

### Host Discovery
Ping scan
nmap -sn 192.168.1.0/24

Single host scan
nmap 192.168.1.1

text

### Port Scanning
Scan top 1000 ports
nmap 192.168.1.1

Scan all ports
nmap -p- 192.168.1.1

Scan specific ports
nmap -p 80,443,22 192.168.1.1

text

### Service Detection
Detect services and versions
nmap -sV 192.168.1.1

OS detection
nmap -O 192.168.1.1

Aggressive scan
nmap -A 192.168.1.1

text

### Stealth Scanning
SYN scan (stealth)
sudo nmap -sS 192.168.1.1

No ping scan
nmap -Pn 192.168.1.1

text

## Practice Lab
Scan your local network
nmap -sn 192.168.1.0/24

Detailed scan of target
nmap -A -T4 target_ip

text

## Notes
- Always get permission before scanning
- Use -T4 for faster scans (but noisier)
- Save results: nmap -oN results.txt target_ip

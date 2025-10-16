#!/bin/bash
echo "🌐 Network Information for CloudSec Sandbox"
echo "==========================================="

echo "📍 Local IP Addresses:"
ip a | grep -E 'inet [0-9]' | grep -v '127.0.0.1'

echo ""
echo "🔌 Active Network Connections:"
ss -tlnp | grep -E ':80|:3000|:22|:3306'

echo ""
echo "🔥 Firewall Status:"
sudo ufw status numbered

echo ""
echo "📊 System Resources:"
echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "Disk: $(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 " used)"}')"

echo ""
echo "🕒 System Uptime:"
uptime

echo "==========================================="

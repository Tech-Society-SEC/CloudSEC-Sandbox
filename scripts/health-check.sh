#!/bin/bash
echo "🔍 CloudSec Sandbox Health Check"
echo "================================="

# Check Apache
if systemctl is-active --quiet apache2; then
    echo "✅ Apache2: Running"
else
    echo "❌ Apache2: Stopped"
fi

# Check MariaDB  
if systemctl is-active --quiet mariadb; then
    echo "✅ MariaDB: Running"
else
    echo "❌ MariaDB: Stopped"
fi

# Check Juice Shop
if systemctl is-active --quiet juice-shop; then
    echo "✅ Juice Shop: Running"
else
    echo "❌ Juice Shop: Stopped"
fi

# Check firewall
echo "🔥 Firewall Status:"
sudo ufw status

# Check open ports
echo "🔌 Open Ports:"
ss -tlnp | grep -E ':80|:3000|:22'

echo "================================="
echo "Health check complete!"

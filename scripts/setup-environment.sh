#!/bin/bash
echo "🚀 Setting up CloudSec Sandbox Environment..."

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install dependencies
echo "🔧 Installing dependencies..."
sudo apt install curl wget git htop net-tools -y

# Start services
echo "🌐 Starting web services..."
sudo systemctl start apache2
sudo systemctl start mariadb
sudo systemctl start juice-shop

# Enable services on boot
sudo systemctl enable apache2
sudo systemctl enable mariadb
sudo systemctl enable juice-shop

echo "✅ Environment setup complete!"
echo "🌐 Access your sandbox at: http://localhost"

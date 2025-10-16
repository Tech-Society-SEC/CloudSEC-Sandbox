# Firewall Configuration

## UFW Rules Applied

sudo ufw allow 80/tcp # HTTP Web Traffic
sudo ufw allow 3000/tcp # Juice Shop
sudo ufw allow 22/tcp # SSH Access
sudo ufw enable

text

## Check Status

sudo ufw status verbose

text

## Port Scanning Prevention
- Only essential ports open
- SSH access restricted
- Web services on standard ports

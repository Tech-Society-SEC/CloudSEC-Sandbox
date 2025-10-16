text
# Database Security Configuration

## MariaDB Hardening Applied

1. Root password set
2. Anonymous users removed  
3. Test database removed
4. Remote root login disabled

## DVWA Database Setup
- Database: `dvwa`
- User: `dvwa`
- Password: `dvwa`
- Privileges: Limited to DVWA database only

## Security Commands

Check database users

sudo mysql -e "SELECT User, Host FROM mysql.user;"
View DVWA database

sudo mysql -e "SHOW DATABASES;"

text
undefined

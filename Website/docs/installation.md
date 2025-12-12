# Secure File Sharing Backend - Installation Guide

## Prerequisites
- PHP 8.1 or higher
- MySQL 8.0 or higher
- Composer
- Web server (Apache/Nginx)

## Installation Steps

### 1. Clone and Setup
```bash
git clone <repository-url>
cd secure-file-sharing
composer install
```

### 2. Database Setup
```bash
# Create database
mysql -u root -p
CREATE DATABASE secure_file_share;
GRANT ALL PRIVILEGES ON secure_file_share.* TO 'your_user'@'localhost';
FLUSH PRIVILEGES;
exit

# Import schema
mysql -u your_user -p secure_file_share < database/schema.sql
```

### 3. Environment Configuration
```bash
# Copy environment template
cp env.example .env

# Edit .env file with your settings
nano .env
```

### 4. Directory Permissions
```bash
# Set proper permissions
chmod 755 storage/
chmod 755 logs/
chmod 644 storage/uploads/
chmod 644 storage/encrypted/
chmod 644 storage/watermarked/
```

### 5. Generate Security Keys
```bash
# Generate JWT secret (32+ characters)
openssl rand -base64 32

# Generate encryption key (32 characters)
openssl rand -hex 16
```

### 6. Web Server Configuration

#### Apache (.htaccess)
```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]

# Security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
```

#### Nginx
```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /path/to/secure-file-sharing;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
}
```

### 7. SSL Configuration (Recommended)
```bash
# Install SSL certificate
# Use Let's Encrypt or your SSL provider
certbot --apache -d your-domain.com
```

### 8. Testing Installation
```bash
# Test API endpoint
curl -X POST http://your-domain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","confirm_password":"password123","first_name":"Test","last_name":"User"}'
```

## Security Checklist

### Database Security
- [ ] Use strong database passwords
- [ ] Limit database user privileges
- [ ] Enable SSL for database connections
- [ ] Regular database backups

### Application Security
- [ ] Set strong JWT secret (32+ characters)
- [ ] Set strong encryption key (32 characters)
- [ ] Configure proper file permissions
- [ ] Enable HTTPS in production
- [ ] Set up firewall rules

### Monitoring
- [ ] Configure log rotation
- [ ] Set up log monitoring
- [ ] Enable security alerts
- [ ] Regular security audits

## Production Deployment

### 1. Environment Variables
```bash
# Production settings
APP_ENV=production
DB_HOST=your-db-host
DB_NAME=secure_file_share
DB_USER=secure_user
DB_PASS=strong_password

JWT_SECRET=your_super_secure_jwt_secret_here
ENCRYPTION_KEY=your_32_char_encryption_key

# Email settings for notifications
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-app-password
```

### 2. Performance Optimization
```bash
# Enable PHP OPcache
opcache.enable=1
opcache.memory_consumption=128
opcache.max_accelerated_files=4000

# Database optimization
innodb_buffer_pool_size=1G
innodb_log_file_size=256M
```

### 3. Backup Strategy
```bash
# Database backup script
#!/bin/bash
mysqldump -u user -p secure_file_share > backup_$(date +%Y%m%d_%H%M%S).sql

# File backup script
tar -czf files_backup_$(date +%Y%m%d_%H%M%S).tar.gz storage/
```

## Troubleshooting

### Common Issues

#### Database Connection Error
- Check database credentials in .env
- Verify database server is running
- Check firewall settings

#### File Upload Issues
- Check directory permissions
- Verify upload_max_filesize in php.ini
- Check post_max_size setting

#### Authentication Issues
- Verify JWT secret is set
- Check token expiration settings
- Ensure proper session configuration

#### Encryption Errors
- Verify encryption key is 32 characters
- Check file permissions on storage directories
- Ensure PHP has proper extensions

### Log Files
- Application logs: `logs/app.log`
- Security logs: `logs/security.log`
- Audit logs: `logs/audit.log`

### Performance Monitoring
```sql
-- Check database performance
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Slow_queries';

-- Monitor file storage usage
du -sh storage/*
```

## Support
For technical support or security concerns, contact the development team.


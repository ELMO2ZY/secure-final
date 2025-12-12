# Database Setup Guide for SecureShare

This guide will help you set up MySQL database using DBeaver and connect it to your SecureShare application.

## Step 1: Install and Setup MySQL

### If you don't have MySQL installed:

1. **Download MySQL:**
   - Go to https://dev.mysql.com/downloads/mysql/
   - Download MySQL Community Server for Windows
   - Install it with default settings
   - Remember your root password!

2. **Start MySQL Service:**
   - Open Services (Win + R, type `services.msc`)
   - Find "MySQL80" or "MySQL"
   - Right-click → Start (if not running)

## Step 2: Install DBeaver

1. **Download DBeaver:**
   - Go to https://dbeaver.io/download/
   - Download DBeaver Community Edition (Free)
   - Install it

## Step 3: Connect to MySQL in DBeaver

1. **Open DBeaver**
2. **Create New Connection:**
   - Click "New Database Connection" (plug icon) or File → New → Database Connection
   - Select **MySQL** from the list
   - Click **Next**

3. **Enter Connection Details:**
   ```
   Host: localhost
   Port: 3306
   Database: (leave empty for now)
   Username: root
   Password: [Your MySQL root password]
   ```
   - Click **Test Connection**
   - If it asks for MySQL driver, click "Download"
   - Click **Finish** when connection succeeds

## Step 4: Create Database in DBeaver

1. **Right-click on your connection** → **SQL Editor** → **New SQL Script**
2. **Copy and paste this SQL:**

```sql
-- Create the database
CREATE DATABASE IF NOT EXISTS secure_file_share 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- Use the database
USE secure_file_share;
```

3. **Click Execute** (or press F5)
4. **Refresh** your connection to see the new database

## Step 5: Create Tables

1. **Open the file:** `database/schema.sql` in DBeaver
2. **Or create a new SQL script** and copy the entire contents of `database/schema.sql`
3. **Make sure you're using the database:**
   ```sql
   USE secure_file_share;
   ```
4. **Execute the entire script** (Select all, then Execute or F5)

This will create all necessary tables:
- `users` - User accounts
- `user_sessions` - Active sessions
- `files` - File records
- `file_shares` - Shared file links
- `audit_logs` - Security audit trail
- `security_alerts` - Security alerts
- And more...

## Step 6: Insert Initial Data

1. **Create a new SQL script** in DBeaver
2. **Copy and paste this SQL:**

```sql
USE secure_file_share;

-- Insert default users (passwords are: admin123, user123, viewer123)
-- In production, these should be hashed with password_hash()
INSERT INTO users (id, email, password_hash, first_name, last_name, role, two_factor_enabled, two_factor_secret) VALUES
('admin_001', 'admin@securefileshare.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Mohamed', 'Loai', 'admin', TRUE, 'JBSWY3DPEHPK3PXP'),
('user_001', 'user@securefileshare.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test', 'User', 'user', FALSE, NULL),
('viewer_001', 'viewer@securefileshare.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test', 'Viewer', 'viewer', FALSE, NULL)
ON DUPLICATE KEY UPDATE 
    email = VALUES(email),
    password_hash = VALUES(password_hash),
    first_name = VALUES(first_name),
    last_name = VALUES(last_name),
    role = VALUES(role);

-- Note: The password hash above is for 'password' - you should change these!
-- To create a new password hash, use this PHP code:
-- password_hash('your_password', PASSWORD_BCRYPT)
```

3. **Execute the script**

## Step 7: Configure Your Application

1. **Create `.env` file** in your project root (copy from `env.example`):

```env
# Database Configuration
DB_HOST=localhost
DB_NAME=secure_file_share
DB_USER=root
DB_PASS=your_mysql_root_password_here

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_minimum_32_characters_long
JWT_EXPIRY=3600

# Encryption Configuration
ENCRYPTION_KEY=your_32_character_encryption_key

# File Storage
UPLOAD_PATH=storage/uploads/
ENCRYPTED_PATH=storage/encrypted/

# Security Settings
MAX_FILE_SIZE=104857600
SESSION_TIMEOUT=1800
MAX_LOGIN_ATTEMPTS=5
```

2. **Replace the values:**
   - `DB_PASS` - Your MySQL root password
   - `JWT_SECRET` - Generate a random 32+ character string
   - `ENCRYPTION_KEY` - Generate a random 32 character string

## Step 8: Test the Connection

1. **In DBeaver**, run this query to verify:
```sql
USE secure_file_share;
SELECT * FROM users;
```

You should see 3 users.

## Step 9: Update Password Hashes (Important!)

The default password hashes are for 'password'. To create proper hashes:

1. **Create a PHP file** `hash_passwords.php`:
```php
<?php
echo password_hash('admin123', PASSWORD_BCRYPT) . "\n";
echo password_hash('user123', PASSWORD_BCRYPT) . "\n";
echo password_hash('viewer123', PASSWORD_BCRYPT) . "\n";
?>
```

2. **Run it:** `php hash_passwords.php`
3. **Update the users table** in DBeaver with the new hashes

## Troubleshooting

### Connection Issues:
- Make sure MySQL service is running
- Check firewall settings
- Verify username/password are correct
- Try `localhost` instead of `127.0.0.1`

### Permission Issues:
- Make sure your MySQL user has CREATE, INSERT, UPDATE, DELETE, SELECT permissions
- For root user, this should work by default

### Character Set Issues:
- Make sure database uses `utf8mb4` charset
- Tables should also use `utf8mb4_unicode_ci` collation

## Next Steps

After setup, the application code will be updated to use the database instead of hardcoded values.



# DBeaver Database Setup - Step by Step Instructions

## Quick Start Guide

Follow these steps to set up your database in DBeaver:

### Step 1: Open DBeaver and Connect to MySQL

1. **Open DBeaver**
2. **Create New Connection:**
   - Click the "New Database Connection" button (plug icon) or go to **File → New → Database Connection**
   - Select **MySQL** from the list
   - Click **Next**

3. **Enter Connection Details:**
   ```
   Host: localhost
   Port: 3306
   Database: (leave empty for now)
   Username: root
   Password: [Enter your MySQL root password]
   ```
   - Click **Test Connection**
   - If it asks to download MySQL driver, click **Download**
   - Click **Finish** when connection succeeds

### Step 2: Create the Database

1. **Right-click on your MySQL connection** → **SQL Editor** → **New SQL Script**
2. **Copy and paste this SQL:**

```sql
CREATE DATABASE IF NOT EXISTS secure_file_share 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE secure_file_share;
```

3. **Click Execute** (or press **F5**)
4. **Refresh** your connection (right-click → Refresh) to see the new database

### Step 3: Create All Tables and Initial Data

1. **Open the file:** `database/complete_setup.sql` in DBeaver
   - Or create a new SQL script and copy the entire contents of `database/complete_setup.sql`
   
2. **Execute the entire script:**
   - Select all (Ctrl+A)
   - Click **Execute** (or press **F5**)

This will:
- ✅ Create all necessary tables
- ✅ Insert default permissions
- ✅ Set up role permissions
- ✅ Insert 3 default users (admin, user, viewer)
- ✅ Show verification counts

### Step 4: Verify Setup

Run this query to verify everything is set up:

```sql
USE secure_file_share;

-- Check users
SELECT id, email, first_name, last_name, role FROM users;

-- Check permissions
SELECT * FROM permissions;

-- Check role permissions
SELECT rp.role_name, p.permission_name 
FROM role_permissions rp
JOIN permissions p ON rp.permission_id = p.id
ORDER BY rp.role_name, p.permission_name;
```

You should see:
- 3 users (admin, user, viewer)
- 9 permissions
- Multiple role-permission mappings

### Step 5: Configure Your Application

1. **Create `.env` file** in your project root (copy from `env.example` if it exists):

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
   - `JWT_SECRET` - Generate a random 32+ character string (you can use: `openssl rand -hex 32`)
   - `ENCRYPTION_KEY` - Generate a random 32 character string

### Step 6: Test Login

Default login credentials:
- **Admin:** `admin@securefileshare.com` / `admin123`
- **User:** `user@securefileshare.com` / `user123`
- **Viewer:** `viewer@securefileshare.com` / `viewer123`

## Troubleshooting

### Connection Issues:
- Make sure MySQL service is running (Windows Services)
- Check firewall settings
- Verify username/password are correct
- Try `localhost` instead of `127.0.0.1`

### Permission Issues:
- Make sure your MySQL user has CREATE, INSERT, UPDATE, DELETE, SELECT permissions
- For root user, this should work by default

### Character Set Issues:
- Make sure database uses `utf8mb4` charset
- Tables should also use `utf8mb4_unicode_ci` collation

### Password Hash Issues:
If you need to generate new password hashes:
1. Run: `php database/generate_password_hashes.php`
2. Copy the generated hashes
3. Update users table in DBeaver

## What's Next?

After setup, the application will:
- ✅ Use database for all user authentication
- ✅ Store files in database instead of sessions
- ✅ Log all activity to audit_logs table
- ✅ Track security alerts
- ✅ Manage permissions from database

## Files Created:

- `database/complete_setup.sql` - Complete setup script (run this!)
- `database/schema.sql` - Just the table structure
- `database/initial_data.sql` - Just the initial data
- `database/generate_password_hashes.php` - Password hash generator
- `DATABASE_SETUP_GUIDE.md` - Detailed guide
- `DBEAVER_SETUP_INSTRUCTIONS.md` - This file (quick reference)





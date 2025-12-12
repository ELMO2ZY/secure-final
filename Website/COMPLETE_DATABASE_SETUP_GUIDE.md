# Complete Database Setup & Integration Guide
## Step-by-Step Instructions for SecureShare

This guide will walk you through setting up MySQL database and integrating it with your website from scratch.

---

## Part 1: Install MySQL (If Not Already Installed)

### Step 1.1: Download MySQL
1. Go to: https://dev.mysql.com/downloads/mysql/
2. Scroll down and click **"MySQL Installer for Windows"**
3. Download the **Windows (x86, 64-bit), MSI Installer** (largest file, ~400MB)
4. Run the installer

### Step 1.2: Install MySQL
1. **Setup Type:** Choose **"Developer Default"** or **"Server only"**
2. **Check Requirements:** Click "Execute" to install missing components if needed
3. **Installation:** Click "Execute" and wait for installation to complete
4. **Configuration:**
   - **Type:** Choose **"Development Computer"**
   - **Port:** Keep default **3306**
   - **Authentication:** Choose **"Use Strong Password Encryption"**
   - **Root Password:** Create a strong password (WRITE IT DOWN!)
   - **Windows Service:** Check **"Start the MySQL Server at System Startup"**
   - **Service Name:** Keep default **"MySQL80"**
5. Click **"Execute"** to apply configuration
6. Click **"Finish"**

### Step 1.3: Verify MySQL is Running
1. Press **Win + R**, type `services.msc`, press Enter
2. Find **"MySQL80"** in the list
3. Check if Status is **"Running"**
4. If not running, right-click → **Start**

---

## Part 2: Install DBeaver (Database Management Tool)

### Step 2.1: Download DBeaver
1. Go to: https://dbeaver.io/download/
2. Click **"Windows Installer"** (Community Edition - Free)
3. Download and run the installer
4. Follow installation wizard (default settings are fine)
5. Launch DBeaver

---

## Part 3: Connect DBeaver to MySQL

### Step 3.1: Create New Connection
1. In DBeaver, click the **"New Database Connection"** button (plug icon) in the toolbar
   - OR go to **File → New → Database Connection**
2. In the connection wizard:
   - Select **"MySQL"** from the list
   - Click **"Next"**

### Step 3.2: Enter Connection Details
Fill in the connection form:
```
Main Tab:
├─ Server Host: localhost
├─ Port: 3306
├─ Database: (leave empty for now)
├─ Username: root
└─ Password: [Enter your MySQL root password]
```

3. Click **"Test Connection"**
4. If it asks to download MySQL driver:
   - Click **"Download"**
   - Wait for download to complete
   - Click **"Test Connection"** again
5. You should see: **"Connected"** message
6. Click **"Finish"**

### Step 3.3: Verify Connection
- You should see your MySQL connection in the left sidebar
- Expand it to see databases (you'll see `information_schema`, `mysql`, `performance_schema`, `sys`)

---

## Part 4: Create the Database

### Step 4.1: Open SQL Editor
1. **Right-click** on your MySQL connection
2. Select **"SQL Editor" → "New SQL Script"**
   - OR click the **"SQL Editor"** button in toolbar

### Step 4.2: Create Database
1. In the SQL Editor, type or copy-paste:

```sql
CREATE DATABASE IF NOT EXISTS secure_file_share 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE secure_file_share;
```

2. **Select all the text** (Ctrl+A)
3. Click **"Execute SQL Script"** button (or press **F5**)
4. You should see: **"SQL script executed successfully"**
5. **Refresh** your connection (right-click connection → Refresh)
6. You should now see **"secure_file_share"** database in the list

---

## Part 5: Create All Tables and Initial Data

### Step 5.1: Open the Setup Script
1. In DBeaver, go to **File → Open File**
2. Navigate to your project folder
3. Open: `database/complete_setup.sql`
   - OR create a new SQL script and copy the entire contents

### Step 5.2: Execute the Script
1. Make sure you're connected to MySQL
2. **Select all** the SQL script (Ctrl+A)
3. Click **"Execute SQL Script"** (or press **F5**)
4. Wait for execution to complete
5. You should see multiple **"SQL script executed successfully"** messages

### Step 5.3: Verify Tables Were Created
1. **Expand** the `secure_file_share` database in the left sidebar
2. **Expand** "Tables"
3. You should see these tables:
   - ✅ `users`
   - ✅ `user_sessions`
   - ✅ `files`
   - ✅ `audit_logs`
   - ✅ `permissions`
   - ✅ `role_permissions`
   - ✅ `security_alerts`

### Step 5.4: Verify Data Was Inserted
1. Right-click on `users` table → **"View Data"**
2. You should see 3 users:
   - admin_001 (Mohamed Loai)
   - user_001 (Test User)
   - viewer_001 (Test Viewer)

---

## Part 6: Configure Your Website (.env File)

### Step 6.1: Create .env File
1. Navigate to your project root folder (where `api.php` is located)
2. Create a new file named: `.env`
   - **Important:** The file must start with a dot (.)
   - If Windows doesn't let you create a file starting with dot:
     - Create `env.txt` first
     - Rename it to `.env` (you may need to enable "Show file extensions" in Windows)

### Step 6.2: Add Configuration
Open `.env` file and add this content:

```env
# Database Configuration
DB_HOST=localhost
DB_NAME=secure_file_share
DB_USER=root
DB_PASS=your_mysql_root_password_here

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_minimum_32_characters_long_12345678901234567890
JWT_EXPIRY=3600

# Encryption Configuration
ENCRYPTION_KEY=your_32_char_encryption_key_1234567890123456

# File Storage
UPLOAD_PATH=storage/uploads/
ENCRYPTED_PATH=storage/encrypted/

# Security Settings
MAX_FILE_SIZE=104857600
SESSION_TIMEOUT=1800
MAX_LOGIN_ATTEMPTS=5
```

### Step 6.3: Replace Values
1. **DB_PASS:** Replace `your_mysql_root_password_here` with your actual MySQL root password
2. **JWT_SECRET:** Replace with a random 32+ character string
   - You can generate one at: https://www.random.org/strings/
   - Or use: `openssl rand -hex 32` in command prompt
3. **ENCRYPTION_KEY:** Replace with a random 32 character string

**Example:**
```env
DB_PASS=MySecurePassword123!
JWT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
ENCRYPTION_KEY=12345678901234567890123456789012
```

### Step 6.4: Save the File
- Save `.env` file in your project root (same folder as `api.php`)

---

## Part 7: Create Storage Directories

### Step 7.1: Create Folders
In your project root, create these folders:
1. `storage/`
2. `storage/uploads/`
3. `storage/encrypted/`

**How to create:**
- Right-click in project folder → New → Folder
- Name it `storage`
- Open `storage` folder → Create `uploads` and `encrypted` folders inside

---

## Part 8: Test the Integration

### Step 8.1: Test Database Connection
1. Open your website in browser
2. Go to login page: `http://website.test/login.html`
3. Try to login with:
   - **Email:** `admin@securefileshare.com`
   - **Password:** `admin123`

### Step 8.2: Check for Errors
- **If login works:** ✅ Database integration is successful!
- **If you see errors:**
  - Check browser console (F12) for JavaScript errors
  - Check PHP error logs
  - Verify `.env` file has correct database password
  - Make sure MySQL service is running

### Step 8.3: Verify Database Activity
1. In DBeaver, right-click `audit_logs` table → **"View Data"**
2. You should see login attempts logged
3. This confirms the website is writing to the database!

---

## Part 9: Verify Everything Works

### Step 9.1: Test All Features
1. **Login:** Use admin credentials
2. **Dashboard:** Should load and show metrics
3. **Upload File:** Try uploading a file
4. **Activity Log:** Check if activities are logged
5. **Files List:** View uploaded files

### Step 9.2: Check Database Tables
In DBeaver, verify data is being stored:

```sql
-- Check users
SELECT * FROM users;

-- Check audit logs (should show your login)
SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10;

-- Check files (after uploading)
SELECT * FROM files;
```

---

## Troubleshooting

### Problem: "Database connection failed"
**Solution:**
1. Check MySQL service is running (services.msc)
2. Verify `.env` file has correct password
3. Check `DB_HOST` is `localhost` (not `127.0.0.1`)
4. Verify database name is `secure_file_share`

### Problem: "Access denied for user 'root'"
**Solution:**
1. Check MySQL root password in `.env` file
2. Try resetting MySQL root password
3. Make sure you're using the correct password

### Problem: "Table doesn't exist"
**Solution:**
1. Make sure you ran `complete_setup.sql` script
2. Verify you're using the correct database (`USE secure_file_share;`)
3. Check if tables exist in DBeaver

### Problem: "Login doesn't work"
**Solution:**
1. Check browser console (F12) for errors
2. Verify users exist in database:
   ```sql
   SELECT * FROM users;
   ```
3. Check password hashes are correct
4. Try regenerating password hashes using `database/generate_password_hashes.php`

### Problem: ".env file not loading"
**Solution:**
1. Make sure file is named exactly `.env` (with dot at start)
2. File must be in project root (same folder as `api.php`)
3. Check file permissions (should be readable)
4. Restart your web server

---

## Quick Reference: Default Login Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@securefileshare.com | admin123 |
| User | user@securefileshare.com | user123 |
| Viewer | viewer@securefileshare.com | viewer123 |

---

## What's Next?

After successful setup:
- ✅ All user authentication uses database
- ✅ File operations will be stored in database
- ✅ Activity logs are automatically recorded
- ✅ Security alerts are tracked
- ✅ Permissions are managed from database

You can now:
- Add new users directly in DBeaver
- View all activity in `audit_logs` table
- Manage permissions through `permissions` and `role_permissions` tables
- Monitor security alerts in `security_alerts` table

---

## Summary Checklist

- [ ] MySQL installed and running
- [ ] DBeaver installed
- [ ] Connected to MySQL in DBeaver
- [ ] Created `secure_file_share` database
- [ ] Executed `complete_setup.sql` script
- [ ] Verified tables and data exist
- [ ] Created `.env` file with correct credentials
- [ ] Created `storage/uploads/` and `storage/encrypted/` folders
- [ ] Tested login successfully
- [ ] Verified database activity in DBeaver

**Once all checkboxes are checked, your database is fully integrated!** 🎉





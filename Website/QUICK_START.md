# Quick Start - Database Setup (5 Minutes)

## Fastest Way to Set Up Database

### 1. Install MySQL (if needed)
- Download from: https://dev.mysql.com/downloads/mysql/
- Install with default settings
- Remember your root password!

### 2. Install DBeaver
- Download from: https://dbeaver.io/download/
- Install and open

### 3. Connect to MySQL in DBeaver
- Click "New Database Connection" → Select "MySQL"
- Enter:
  - Host: `localhost`
  - Port: `3306`
  - Username: `root`
  - Password: [Your MySQL password]
- Click "Test Connection" → "Finish"

### 4. Create Database
- Right-click connection → "SQL Editor" → "New SQL Script"
- Copy and paste:
```sql
CREATE DATABASE IF NOT EXISTS secure_file_share 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE secure_file_share;
```
- Press F5 to execute

### 5. Run Setup Script
- Open `database/complete_setup.sql` in DBeaver
- Select all (Ctrl+A)
- Press F5 to execute
- Wait for "SQL script executed successfully"

### 6. Create .env File
- In project root, create `.env` file
- Add:
```env
DB_HOST=localhost
DB_NAME=secure_file_share
DB_USER=root
DB_PASS=your_mysql_password_here
JWT_SECRET=your_random_32_character_string_here
ENCRYPTION_KEY=your_32_character_key_here
```
- Replace `your_mysql_password_here` with your actual MySQL password

### 7. Create Storage Folders
- Create `storage/uploads/` folder
- Create `storage/encrypted/` folder

### 8. Test Login
- Go to: `http://website.test/login.html`
- Login with: `admin@securefileshare.com` / `admin123`
- ✅ If it works, you're done!

---

**For detailed instructions, see: `COMPLETE_DATABASE_SETUP_GUIDE.md`**





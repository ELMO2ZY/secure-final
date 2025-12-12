# Migration Guide - Removing Hardcoded Values

This guide explains the changes made to remove all hardcoded values and replace them with database-backed implementations.

## Changes Made

### 1. Database-Backed Authentication
- **Before**: Hardcoded user credentials in `api.php`
- **After**: All users stored in database with password hashing
- **Files Changed**: `api.php`, `config.php` (new)

### 2. Environment Variables
- **Before**: Hardcoded encryption keys and secrets
- **After**: All secrets loaded from `.env` file
- **Files Changed**: `config.php` (new), `env.example`

### 3. File Storage
- **Before**: Files stored in PHP sessions (temporary)
- **After**: Files stored in database and filesystem
- **Files Changed**: `api.php`

### 4. User Management
- **Before**: No user registration
- **After**: Full signup functionality with database storage
- **Files Changed**: `signup.html`, `api.php`

## Setup Instructions

### Step 1: Database Setup

1. Create the database:
```sql
CREATE DATABASE secure_file_share;
```

2. Import the schema:
```bash
mysql -u your_user -p secure_file_share < database/schema.sql
```

### Step 2: Environment Configuration

1. Copy the example environment file:
```bash
cp env.example .env
```

2. Edit `.env` with your settings:
```env
# Database Configuration
DB_HOST=localhost
DB_NAME=secure_file_share
DB_USER=your_db_user
DB_PASS=your_secure_password

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here_minimum_32_chars
JWT_EXPIRY=3600

# Encryption Configuration
ENCRYPTION_KEY=your_32_character_encryption_key_here

# Admin Setup (for creating first admin)
ADMIN_SETUP_SECRET=change_me_in_production
```

3. Generate secure keys:
```bash
# Generate JWT secret (32+ characters)
openssl rand -base64 32

# Generate encryption key (32 characters)
openssl rand -hex 16
```

### Step 3: Create Storage Directories

```bash
mkdir -p storage/uploads
mkdir -p storage/encrypted
chmod 755 storage/uploads
chmod 755 storage/encrypted
```

### Step 4: Create First Admin User

1. Access `setup_admin.php` in your browser
2. Enter the secret key from your `.env` file (ADMIN_SETUP_SECRET)
3. Fill in admin user details
4. Submit to create the admin account

**OR** create manually in database:
```sql
INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, created_at)
VALUES (
    UNHEX(REPLACE(UUID(), '-', '')),
    'admin@example.com',
    '$2y$10$YourHashedPasswordHere',
    'Admin',
    'User',
    'admin',
    1,
    NOW()
);
```

### Step 5: Delete Demo Files (Optional)

After setup is complete, you can delete:
- `api_backup.php` (old hardcoded version)
- `setup_admin.php` (if you want, but keep it secure for future use)
- Demo credentials from `README.md` and frontend files

## Important Notes

1. **No More Hardcoded Users**: All authentication now uses the database
2. **Password Security**: All passwords are hashed using `password_hash()` (bcrypt)
3. **File Persistence**: Files are now stored permanently (until expiry) instead of in sessions
4. **Audit Logging**: All actions are logged to the `audit_logs` table
5. **Session Management**: User sessions are stored in `user_sessions` table

## Verification

To verify everything is working:

1. Create an admin user using `setup_admin.php`
2. Login at `login.html` with admin credentials
3. Upload a file - it should be stored in `storage/encrypted/`
4. Check the database:
   - User should be in `users` table
   - File metadata in `files` table
   - Audit log entry in `audit_logs` table

## Troubleshooting

### Database Connection Issues
- Check `.env` file has correct database credentials
- Ensure MySQL is running
- Verify database exists

### Permission Errors
- Check file permissions on `storage/` directories
- Ensure web server can write to storage directories

### Login Not Working
- Verify user exists in database
- Check password is hashed correctly
- Look at `audit_logs` table for error details

## Next Steps

1. Configure your production environment variables
2. Set up proper backup procedures for database and encrypted files
3. Review and customize user roles and permissions
4. Set up monitoring and alerting


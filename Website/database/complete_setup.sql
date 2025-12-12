-- Complete Database Setup Script for SecureShare
-- Run this entire script in DBeaver to set up your database

-- Step 1: Create Database
CREATE DATABASE IF NOT EXISTS secure_file_share 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE secure_file_share;

-- Step 2: Create Tables (from schema.sql)
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(32) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role ENUM('admin', 'user', 'viewer') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255) NULL,
    failed_login_attempts INT DEFAULT 0,
    last_login_attempt TIMESTAMP NULL,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_email (email),
    INDEX idx_role (role),
    INDEX idx_active (is_active)
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_session_id (session_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
);

-- Files table
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_id VARCHAR(32) UNIQUE NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    encrypted_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    encrypted_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_hash VARCHAR(64) NOT NULL,
    encrypted_file_key TEXT NOT NULL,
    watermark_data JSON NULL,
    expires_at TIMESTAMP NULL,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_file_id (file_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_created_at (created_at)
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(32) NULL,
    action VARCHAR(100) NULL,
    success BOOLEAN NULL,
    description TEXT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    session_id VARCHAR(64) NULL,
    metadata JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_event_type (event_type),
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_ip_address (ip_address)
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role permissions table
CREATE TABLE IF NOT EXISTS role_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL,
    permission_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE KEY unique_role_permission (role_name, permission_id)
);

-- Security alerts table
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT NOT NULL,
    user_id VARCHAR(32) NULL,
    ip_address VARCHAR(45) NULL,
    metadata JSON NULL,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_alert_type (alert_type),
    INDEX idx_severity (severity),
    INDEX idx_created_at (created_at),
    INDEX idx_is_resolved (is_resolved)
);

-- Step 3: Insert Default Permissions
INSERT INTO permissions (permission_name, description) VALUES
('file.upload', 'Upload files'),
('file.download', 'Download files'),
('file.share', 'Share files with others'),
('file.delete', 'Delete own files'),
('file.view_all', 'View all files in system'),
('user.manage', 'Manage user accounts'),
('system.admin', 'System administration'),
('audit.view', 'View audit logs'),
('security.alerts', 'View security alerts')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- Step 4: Insert Role Permissions
-- Admin permissions (all)
INSERT INTO role_permissions (role_name, permission_id) 
SELECT 'admin', id FROM permissions
ON DUPLICATE KEY UPDATE permission_id = VALUES(permission_id);

-- User permissions
INSERT INTO role_permissions (role_name, permission_id) 
SELECT 'user', id FROM permissions WHERE permission_name IN ('file.upload', 'file.download', 'file.share', 'file.delete')
ON DUPLICATE KEY UPDATE permission_id = VALUES(permission_id);

-- Viewer permissions
INSERT INTO role_permissions (role_name, permission_id) 
SELECT 'viewer', id FROM permissions WHERE permission_name = 'file.download'
ON DUPLICATE KEY UPDATE permission_id = VALUES(permission_id);

-- Step 5: Insert Default Users
-- Note: These password hashes are for: admin123, user123, viewer123
-- To generate new hashes, run: php database/generate_password_hashes.php
INSERT INTO users (id, email, password_hash, first_name, last_name, role, two_factor_enabled, two_factor_secret, is_active) VALUES
('admin_001', 'admin@securefileshare.com', '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'Mohamed', 'Loai', 'admin', TRUE, 'JBSWY3DPEHPK3PXP', TRUE),
('user_001', 'user@securefileshare.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test', 'User', 'user', FALSE, NULL, TRUE),
('viewer_001', 'viewer@securefileshare.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test', 'Viewer', 'viewer', FALSE, NULL, TRUE)
ON DUPLICATE KEY UPDATE 
    email = VALUES(email),
    password_hash = VALUES(password_hash),
    first_name = VALUES(first_name),
    last_name = VALUES(last_name),
    role = VALUES(role),
    is_active = VALUES(is_active);

-- Step 6: Verify Setup
SELECT 'Database setup complete!' as status;
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as permission_count FROM permissions;
SELECT COUNT(*) as role_permission_count FROM role_permissions;



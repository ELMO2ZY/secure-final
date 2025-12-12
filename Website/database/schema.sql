-- Secure File Sharing & Data Leak Prevention Database Schema
-- Created for backend security implementation

-- Users table
CREATE TABLE users (
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
CREATE TABLE user_sessions (
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

-- User encryption keys table
CREATE TABLE user_encryption_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL,
    encryption_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_key (user_id)
);

-- Files table
CREATE TABLE files (
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

-- File shares table
CREATE TABLE file_shares (
    id INT AUTO_INCREMENT PRIMARY KEY,
    share_id VARCHAR(32) UNIQUE NOT NULL,
    file_id VARCHAR(32) NOT NULL,
    shared_by VARCHAR(32) NOT NULL,
    shared_with VARCHAR(32) NOT NULL,
    permissions ENUM('read', 'download', 'view') DEFAULT 'read',
    expires_at TIMESTAMP NULL,
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_share_id (share_id),
    INDEX idx_file_id (file_id),
    INDEX idx_shared_with (shared_with),
    INDEX idx_expires_at (expires_at)
);

-- Audit logs table
CREATE TABLE audit_logs (
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

-- Rate limits table
CREATE TABLE rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_ip_address (ip_address),
    INDEX idx_created_at (created_at)
);

-- Permissions table
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role permissions table
CREATE TABLE role_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL,
    permission_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE KEY unique_role_permission (role_name, permission_id)
);

-- Security alerts table
CREATE TABLE security_alerts (
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

-- Insert default permissions
INSERT INTO permissions (permission_name, description) VALUES
('file.upload', 'Upload files'),
('file.download', 'Download files'),
('file.share', 'Share files with others'),
('file.delete', 'Delete own files'),
('file.view_all', 'View all files in system'),
('user.manage', 'Manage user accounts'),
('system.admin', 'System administration'),
('audit.view', 'View audit logs'),
('security.alerts', 'View security alerts');

-- Insert role permissions
INSERT INTO role_permissions (role_name, permission_id) VALUES
-- Admin permissions
('admin', 1), ('admin', 2), ('admin', 3), ('admin', 4), ('admin', 5), ('admin', 6), ('admin', 7), ('admin', 8), ('admin', 9),
-- User permissions
('user', 1), ('user', 2), ('user', 3), ('user', 4),
-- Viewer permissions
('viewer', 2);

-- Create indexes for better performance
CREATE INDEX idx_files_user_created ON files(user_id, created_at);
CREATE INDEX idx_audit_logs_type_created ON audit_logs(event_type, created_at);
CREATE INDEX idx_file_shares_expires ON file_shares(expires_at, is_revoked);

-- Create views for common queries
CREATE VIEW active_file_shares AS
SELECT 
    fs.*,
    f.original_name,
    f.file_size,
    f.mime_type,
    u1.email as shared_by_email,
    u2.email as shared_with_email
FROM file_shares fs
JOIN files f ON fs.file_id = f.file_id
JOIN users u1 ON fs.shared_by = u1.id
JOIN users u2 ON fs.shared_with = u2.id
WHERE fs.is_revoked = FALSE 
AND (fs.expires_at IS NULL OR fs.expires_at > NOW())
AND f.is_deleted = FALSE;

CREATE VIEW user_file_stats AS
SELECT 
    u.id as user_id,
    u.email,
    COUNT(f.id) as total_files,
    SUM(f.file_size) as total_size,
    COUNT(fs.id) as shared_files,
    MAX(f.created_at) as last_upload
FROM users u
LEFT JOIN files f ON u.id = f.user_id AND f.is_deleted = FALSE
LEFT JOIN file_shares fs ON f.file_id = fs.file_id AND fs.is_revoked = FALSE
GROUP BY u.id, u.email;


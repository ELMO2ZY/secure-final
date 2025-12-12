-- Initial Data for SecureShare Database
-- Run this AFTER creating the tables from schema.sql

USE secure_file_share;

-- Insert default users with proper password hashes
-- Passwords: admin123, user123, viewer123
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

-- Note: To generate new password hashes, use this PHP code:
-- <?php echo password_hash('your_password', PASSWORD_BCRYPT); ?>



<?php

/**
 * Security Configuration for Secure File Sharing System
 * This file contains all security-related configurations and constants
 */

namespace SecureFileShare\Config;

class SecurityConfig
{
    // Encryption Configuration
    const ENCRYPTION_ALGORITHM = 'AES-256-GCM';
    const ENCRYPTION_KEY_LENGTH = 32;
    const FILE_KEY_LENGTH = 32;
    
    // JWT Configuration
    const JWT_ALGORITHM = 'HS256';
    const JWT_ISSUER = 'secure-file-share';
    const JWT_AUDIENCE = 'secure-file-share-users';
    const DEFAULT_TOKEN_EXPIRY = 3600; // 1 hour
    const REFRESH_TOKEN_EXPIRY = 86400; // 24 hours
    
    // Password Configuration
    const MIN_PASSWORD_LENGTH = 8;
    const MAX_PASSWORD_LENGTH = 128;
    const PASSWORD_REQUIRE_UPPERCASE = true;
    const PASSWORD_REQUIRE_LOWERCASE = true;
    const PASSWORD_REQUIRE_NUMBERS = true;
    const PASSWORD_REQUIRE_SYMBOLS = true;
    
    // File Upload Configuration
    const MAX_FILE_SIZE = 104857600; // 100MB
    const ALLOWED_FILE_TYPES = [
        'pdf', 'doc', 'docx', 'txt', 'rtf',
        'jpg', 'jpeg', 'png', 'gif', 'bmp',
        'xlsx', 'xls', 'ppt', 'pptx',
        'zip', 'rar', '7z'
    ];
    const MAX_FILES_PER_USER = 1000;
    
    // Session Configuration
    const SESSION_TIMEOUT = 1800; // 30 minutes
    const SESSION_REGENERATE_INTERVAL = 300; // 5 minutes
    const MAX_CONCURRENT_SESSIONS = 5;
    
    // Rate Limiting Configuration
    const RATE_LIMIT_PER_MINUTE = 60;
    const RATE_LIMIT_PER_HOUR = 1000;
    const RATE_LIMIT_BURST = 10;
    const RATE_LIMIT_WINDOW = 60; // seconds
    
    // Login Security Configuration
    const MAX_LOGIN_ATTEMPTS = 5;
    const LOGIN_LOCKOUT_DURATION = 900; // 15 minutes
    const PASSWORD_RESET_EXPIRY = 3600; // 1 hour
    const ACCOUNT_LOCKOUT_DURATION = 86400; // 24 hours
    
    // Two-Factor Authentication Configuration
    const TOTP_WINDOW = 1; // Allow 1 window of tolerance
    const TOTP_PERIOD = 30; // 30 seconds
    const BACKUP_CODES_COUNT = 10;
    const BACKUP_CODE_LENGTH = 8;
    
    // File Sharing Configuration
    const DEFAULT_SHARE_EXPIRY = 86400; // 24 hours
    const MAX_SHARE_EXPIRY = 604800; // 7 days
    const MAX_SHARES_PER_FILE = 50;
    const SHARE_LINK_LENGTH = 32;
    
    // Audit and Monitoring Configuration
    const AUDIT_LOG_RETENTION_DAYS = 365;
    const SECURITY_LOG_RETENTION_DAYS = 90;
    const LOG_ROTATION_SIZE = 10485760; // 10MB
    const MAX_LOG_FILES = 10;
    
    // Security Headers Configuration
    const SECURITY_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()'
    ];
    
    // CORS Configuration
    const CORS_ALLOWED_ORIGINS = [];
    const CORS_ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
    const CORS_ALLOWED_HEADERS = ['Content-Type', 'Authorization', 'X-CSRF-Token'];
    const CORS_MAX_AGE = 86400; // 24 hours
    
    // CSRF Configuration
    const CSRF_TOKEN_LENGTH = 32;
    const CSRF_TOKEN_EXPIRY = 3600; // 1 hour
    const CSRF_TOKEN_REGENERATE_INTERVAL = 300; // 5 minutes
    
    // Input Validation Configuration
    const MAX_INPUT_LENGTH = 10000;
    const MAX_JSON_DEPTH = 10;
    const MAX_JSON_SIZE = 1048576; // 1MB
    
    // File Validation Configuration
    const SCAN_FILE_CONTENT = true;
    const CHECK_FILE_SIGNATURES = true;
    const MAX_FILE_NAME_LENGTH = 255;
    const ALLOWED_FILE_NAME_CHARS = '/^[a-zA-Z0-9._-]+$/';
    
    // Watermarking Configuration
    const WATERMARK_VISIBLE_OPACITY = 0.3;
    const WATERMARK_INVISIBLE_BITS = 1;
    const WATERMARK_TEXT_SIZE = 12;
    const WATERMARK_POSITION = 'bottom-right';
    
    // Backup Configuration
    const BACKUP_ENCRYPTION_ENABLED = true;
    const BACKUP_COMPRESSION_ENABLED = true;
    const BACKUP_RETENTION_DAYS = 30;
    const BACKUP_SCHEDULE = '0 2 * * *'; // Daily at 2 AM
    
    // Security Scanning Configuration
    const VIRUS_SCAN_ENABLED = false; // Requires ClamAV
    const MALWARE_SCAN_ENABLED = true;
    const CONTENT_SCAN_ENABLED = true;
    const SCAN_TIMEOUT = 30; // seconds
    
    // Database Security Configuration
    const DB_CONNECTION_TIMEOUT = 30;
    const DB_QUERY_TIMEOUT = 60;
    const DB_MAX_CONNECTIONS = 100;
    const DB_SSL_REQUIRED = true;
    
    // Email Security Configuration
    const EMAIL_ENCRYPTION_ENABLED = true;
    const EMAIL_SIGNING_ENABLED = true;
    const EMAIL_RATE_LIMIT = 10; // per hour
    const EMAIL_MAX_RECIPIENTS = 50;
    
    // API Security Configuration
    const API_VERSION = 'v1';
    const API_RATE_LIMIT_ENABLED = true;
    const API_REQUEST_TIMEOUT = 30;
    const API_MAX_REQUEST_SIZE = 10485760; // 10MB
    
    // Logging Configuration
    const LOG_LEVELS = [
        'emergency' => 0,
        'alert' => 1,
        'critical' => 2,
        'error' => 3,
        'warning' => 4,
        'notice' => 5,
        'info' => 6,
        'debug' => 7
    ];
    
    const DEFAULT_LOG_LEVEL = 'info';
    const SECURITY_LOG_LEVEL = 'warning';
    const AUDIT_LOG_LEVEL = 'info';
    
    // Threat Detection Configuration
    const SUSPICIOUS_ACTIVITY_THRESHOLDS = [
        'failed_logins_per_hour' => 10,
        'file_access_per_hour' => 100,
        'api_calls_per_minute' => 200,
        'unusual_ip_addresses' => 3,
        'large_file_uploads' => 5
    ];
    
    // Security Alerts Configuration
    const ALERT_SEVERITY_LEVELS = [
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4
    ];
    
    const ALERT_NOTIFICATION_METHODS = [
        'email' => true,
        'sms' => false,
        'webhook' => false,
        'log' => true
    ];
    
    // Compliance Configuration
    const GDPR_COMPLIANCE_ENABLED = true;
    const DATA_RETENTION_POLICY_DAYS = 2555; // 7 years
    const RIGHT_TO_BE_FORGOTTEN_ENABLED = true;
    const DATA_EXPORT_ENABLED = true;
    
    // Performance Configuration
    const CACHE_ENABLED = true;
    const CACHE_TTL = 3600; // 1 hour
    const CACHE_MAX_SIZE = 104857600; // 100MB
    const CACHE_CLEANUP_INTERVAL = 3600; // 1 hour
    
    // Monitoring Configuration
    const HEALTH_CHECK_ENABLED = true;
    const HEALTH_CHECK_INTERVAL = 60; // seconds
    const METRICS_COLLECTION_ENABLED = true;
    const PERFORMANCE_MONITORING_ENABLED = true;
    
    /**
     * Get security configuration value
     */
    public static function get(string $key, $default = null)
    {
        $reflection = new \ReflectionClass(self::class);
        $constants = $reflection->getConstants();
        
        return $constants[$key] ?? $default;
    }
    
    /**
     * Validate security configuration
     */
    public static function validate(): array
    {
        $errors = [];
        
        // Validate encryption key length
        if (strlen($_ENV['ENCRYPTION_KEY'] ?? '') < self::ENCRYPTION_KEY_LENGTH) {
            $errors[] = 'Encryption key must be at least ' . self::ENCRYPTION_KEY_LENGTH . ' characters';
        }
        
        // Validate JWT secret length
        if (strlen($_ENV['JWT_SECRET'] ?? '') < 32) {
            $errors[] = 'JWT secret must be at least 32 characters';
        }
        
        // Validate file upload path
        $uploadPath = $_ENV['UPLOAD_PATH'] ?? '';
        if (!is_dir($uploadPath) || !is_writable($uploadPath)) {
            $errors[] = 'Upload path must be a writable directory';
        }
        
        return $errors;
    }
    
    /**
     * Get security recommendations
     */
    public static function getRecommendations(): array
    {
        return [
            'Enable HTTPS in production',
            'Use strong, unique passwords for all accounts',
            'Enable two-factor authentication for all users',
            'Regular security updates and patches',
            'Monitor audit logs regularly',
            'Implement regular backups',
            'Use firewall and intrusion detection',
            'Regular security assessments',
            'Employee security training',
            'Incident response plan'
        ];
    }
}


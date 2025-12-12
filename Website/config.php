<?php
/**
 * Configuration file - Loads environment variables and provides database connection
 */

// Load environment variables from .env file if it exists
if (file_exists(__DIR__ . '/.env')) {
    $lines = file(__DIR__ . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue; // Skip comments
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $_ENV[trim($key)] = trim($value);
        }
    }
}

// Database configuration
define('DB_HOST', $_ENV['DB_HOST'] ?? 'localhost');
define('DB_NAME', $_ENV['DB_NAME'] ?? 'secure_file_share');
define('DB_USER', $_ENV['DB_USER'] ?? 'root');
define('DB_PASS', $_ENV['DB_PASS'] ?? '');
define('DB_CHARSET', 'utf8mb4');

// JWT Configuration
define('JWT_SECRET', $_ENV['JWT_SECRET'] ?? bin2hex(random_bytes(32)));
define('JWT_EXPIRY', intval($_ENV['JWT_EXPIRY'] ?? 3600));

// Encryption Configuration
define('ENCRYPTION_KEY', $_ENV['ENCRYPTION_KEY'] ?? bin2hex(random_bytes(16)));

// File Storage Paths
define('UPLOAD_PATH', $_ENV['UPLOAD_PATH'] ?? __DIR__ . '/storage/uploads/');
define('ENCRYPTED_PATH', $_ENV['ENCRYPTED_PATH'] ?? __DIR__ . '/storage/encrypted/');

// Security Settings
define('MAX_FILE_SIZE', intval($_ENV['MAX_FILE_SIZE'] ?? 104857600)); // 100MB
define('SESSION_TIMEOUT', intval($_ENV['SESSION_TIMEOUT'] ?? 1800));
define('MAX_LOGIN_ATTEMPTS', intval($_ENV['MAX_LOGIN_ATTEMPTS'] ?? 5));

/**
 * Get database connection
 */
function getDatabase() {
    static $db = null;
    
    if ($db === null) {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];
            $db = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed. Please check your configuration.");
        }
    }
    
    return $db;
}

/**
 * Ensure storage directories exist
 */
function ensureStorageDirectories() {
    $directories = [UPLOAD_PATH, ENCRYPTED_PATH];
    foreach ($directories as $dir) {
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
        }
    }
}

// Initialize storage directories
ensureStorageDirectories();


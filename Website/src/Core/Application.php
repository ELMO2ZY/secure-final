<?php

namespace SecureFileShare\Core;

use Dotenv\Dotenv;
use PDO;
use PDOException;

class Application
{
    private static $instance = null;
    private $config = [];
    private $db = null;
    private $logger = null;

    private function __construct()
    {
        $this->loadEnvironment();
        $this->initializeDatabase();
        $this->initializeLogger();
        $this->setSecurityHeaders();
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function loadEnvironment(): void
    {
        if (file_exists(__DIR__ . '/../../.env')) {
            $dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
            $dotenv->load();
        }

        $this->config = [
            'db_host' => $_ENV['DB_HOST'] ?? 'localhost',
            'db_name' => $_ENV['DB_NAME'] ?? 'secure_file_share',
            'db_user' => $_ENV['DB_USER'] ?? 'root',
            'db_pass' => $_ENV['DB_PASS'] ?? '',
            'jwt_secret' => $_ENV['JWT_SECRET'] ?? '',
            'jwt_expiry' => $_ENV['JWT_EXPIRY'] ?? 3600,
            'encryption_key' => $_ENV['ENCRYPTION_KEY'] ?? '',
            'max_file_size' => $_ENV['MAX_FILE_SIZE'] ?? 104857600,
            'allowed_file_types' => explode(',', $_ENV['ALLOWED_FILE_TYPES'] ?? 'pdf,doc,docx,txt'),
            'session_timeout' => $_ENV['SESSION_TIMEOUT'] ?? 1800,
            'max_login_attempts' => $_ENV['MAX_LOGIN_ATTEMPTS'] ?? 5,
            'rate_limit_per_minute' => $_ENV['RATE_LIMIT_PER_MINUTE'] ?? 60,
            'upload_path' => $_ENV['UPLOAD_PATH'] ?? 'storage/uploads/',
            'encrypted_path' => $_ENV['ENCRYPTED_PATH'] ?? 'storage/encrypted/',
            'watermark_path' => $_ENV['WATERMARK_PATH'] ?? 'storage/watermarked/',
        ];
    }

    private function initializeDatabase(): void
    {
        try {
            $dsn = "mysql:host={$this->config['db_host']};dbname={$this->config['db_name']};charset=utf8mb4";
            $this->db = new PDO($dsn, $this->config['db_user'], $this->config['db_pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ]);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new \Exception("Database connection failed");
        }
    }

    private function initializeLogger(): void
    {
        $this->logger = new \Monolog\Logger('secure_file_share');
        $handler = new \Monolog\Handler\StreamHandler(__DIR__ . '/../../logs/app.log');
        $this->logger->pushHandler($handler);
    }

    private function setSecurityHeaders(): void
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'');
        
        if (isset($_ENV['CORS_ORIGINS'])) {
            $origins = explode(',', $_ENV['CORS_ORIGINS']);
            $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
            if (in_array($origin, $origins)) {
                header("Access-Control-Allow-Origin: $origin");
            }
        }
        
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
        header('Access-Control-Allow-Credentials: true');
    }

    public function getConfig(string $key = null)
    {
        if ($key === null) {
            return $this->config;
        }
        return $this->config[$key] ?? null;
    }

    public function getDatabase(): PDO
    {
        return $this->db;
    }

    public function getLogger(): \Monolog\Logger
    {
        return $this->logger;
    }

    public function handleCORS(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit();
        }
    }
}


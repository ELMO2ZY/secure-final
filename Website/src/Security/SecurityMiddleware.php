<?php

namespace SecureFileShare\Security;

use SecureFileShare\Core\Application;

class SecurityMiddleware
{
    private $app;
    private $rateLimiter;
    private $csrfProtection;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->rateLimiter = new RateLimiter();
        $this->csrfProtection = new CSRFProtection();
    }

    /**
     * Apply security middleware to request
     */
    public function handleRequest(): bool
    {
        // Handle CORS preflight
        $this->app->handleCORS();

        // Rate limiting
        if (!$this->rateLimiter->checkLimit()) {
            $this->app->getLogger()->warning('Rate limit exceeded', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
            $this->sendErrorResponse(429, 'Rate limit exceeded');
            return false;
        }

        // CSRF protection for state-changing requests
        if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            if (!$this->csrfProtection->validateToken()) {
                $this->app->getLogger()->warning('CSRF token validation failed', [
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    'method' => $_SERVER['REQUEST_METHOD']
                ]);
                $this->sendErrorResponse(403, 'CSRF token validation failed');
                return false;
            }
        }

        // Input validation and sanitization
        $this->sanitizeInputs();

        // SQL injection prevention (already handled by PDO prepared statements)
        // XSS prevention
        $this->preventXSS();

        return true;
    }

    /**
     * Validate file upload
     */
    public function validateFileUpload(array $file): array
    {
        $errors = [];
        $maxSize = $this->app->getConfig('max_file_size');
        $allowedTypes = $this->app->getConfig('allowed_file_types');

        // Check file size
        if ($file['size'] > $maxSize) {
            $errors[] = "File size exceeds maximum allowed size of " . $this->formatBytes($maxSize);
        }

        // Check file type
        $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($fileExtension, $allowedTypes)) {
            $errors[] = "File type '$fileExtension' is not allowed. Allowed types: " . implode(', ', $allowedTypes);
        }

        // Check for malicious file content
        if (!$this->scanFileContent($file['tmp_name'])) {
            $errors[] = "File contains potentially malicious content";
        }

        // Check file name for dangerous characters
        if (!$this->validateFileName($file['name'])) {
            $errors[] = "File name contains invalid characters";
        }

        return $errors;
    }

    /**
     * Validate user input
     */
    public function validateInput(array $data, array $rules): array
    {
        $errors = [];

        foreach ($rules as $field => $rule) {
            $value = $data[$field] ?? null;

            // Required field check
            if (isset($rule['required']) && $rule['required'] && empty($value)) {
                $errors[$field] = "Field '$field' is required";
                continue;
            }

            // Skip validation if field is empty and not required
            if (empty($value) && !isset($rule['required'])) {
                continue;
            }

            // Type validation
            if (isset($rule['type'])) {
                switch ($rule['type']) {
                    case 'email':
                        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                            $errors[$field] = "Invalid email format";
                        }
                        break;
                    case 'int':
                        if (!is_numeric($value) || (int)$value != $value) {
                            $errors[$field] = "Must be an integer";
                        }
                        break;
                    case 'string':
                        if (!is_string($value)) {
                            $errors[$field] = "Must be a string";
                        }
                        break;
                }
            }

            // Length validation
            if (isset($rule['min_length']) && strlen($value) < $rule['min_length']) {
                $errors[$field] = "Minimum length is {$rule['min_length']} characters";
            }
            if (isset($rule['max_length']) && strlen($value) > $rule['max_length']) {
                $errors[$field] = "Maximum length is {$rule['max_length']} characters";
            }

            // Pattern validation
            if (isset($rule['pattern']) && !preg_match($rule['pattern'], $value)) {
                $errors[$field] = "Invalid format";
            }
        }

        return $errors;
    }

    /**
     * Sanitize input data
     */
    private function sanitizeInputs(): void
    {
        // Sanitize GET parameters
        $_GET = $this->sanitizeArray($_GET);
        
        // Sanitize POST parameters
        $_POST = $this->sanitizeArray($_POST);
        
        // Sanitize COOKIE parameters
        $_COOKIE = $this->sanitizeArray($_COOKIE);
    }

    /**
     * Sanitize array recursively
     */
    private function sanitizeArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->sanitizeArray($value);
            } else {
                $data[$key] = $this->sanitizeValue($value);
            }
        }
        return $data;
    }

    /**
     * Sanitize single value
     */
    private function sanitizeValue($value): string
    {
        if (!is_string($value)) {
            return $value;
        }

        // Remove null bytes
        $value = str_replace("\0", '', $value);
        
        // Trim whitespace
        $value = trim($value);
        
        // Remove control characters except newlines and tabs
        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $value);
        
        return $value;
    }

    /**
     * Prevent XSS attacks
     */
    private function preventXSS(): void
    {
        // Set XSS protection headers
        header('X-XSS-Protection: 1; mode=block');
        
        // Content Security Policy
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    }

    /**
     * Scan file content for malicious patterns
     */
    private function scanFileContent(string $filePath): bool
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return false;
        }

        // Check for executable signatures
        $executableSignatures = [
            'MZ', // Windows executable
            'ELF', // Linux executable
            '#!/', // Shell script
            '<?php', // PHP script
            '<script', // JavaScript
            'javascript:', // JavaScript protocol
        ];

        foreach ($executableSignatures as $signature) {
            if (strpos($content, $signature) !== false) {
                return false;
            }
        }

        // Check for suspicious patterns
        $suspiciousPatterns = [
            '/eval\s*\(/i',
            '/base64_decode/i',
            '/system\s*\(/i',
            '/exec\s*\(/i',
            '/shell_exec/i',
            '/passthru/i',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate file name
     */
    private function validateFileName(string $fileName): bool
    {
        // Check for dangerous characters
        $dangerousChars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|'];
        
        foreach ($dangerousChars as $char) {
            if (strpos($fileName, $char) !== false) {
                return false;
            }
        }

        // Check length
        if (strlen($fileName) > 255) {
            return false;
        }

        // Check for reserved names (Windows)
        $reservedNames = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'];
        $nameWithoutExt = pathinfo($fileName, PATHINFO_FILENAME);
        
        if (in_array(strtoupper($nameWithoutExt), $reservedNames)) {
            return false;
        }

        return true;
    }

    /**
     * Format bytes to human readable format
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= pow(1024, $pow);
        
        return round($bytes, 2) . ' ' . $units[$pow];
    }

    /**
     * Send error response
     */
    private function sendErrorResponse(int $code, string $message): void
    {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => true,
            'code' => $code,
            'message' => $message,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        exit;
    }
}

/**
 * Rate Limiter Class
 */
class RateLimiter
{
    private $app;

    public function __construct()
    {
        $this->app = Application::getInstance();
    }

    public function checkLimit(): bool
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $limit = $this->app->getConfig('rate_limit_per_minute');
        
        $db = $this->app->getDatabase();
        
        // Clean old entries
        $stmt = $db->prepare("DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
        $stmt->execute();
        
        // Check current count
        $stmt = $db->prepare("
            SELECT COUNT(*) FROM rate_limits 
            WHERE ip_address = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        ");
        $stmt->execute([$ip]);
        $count = $stmt->fetchColumn();
        
        if ($count >= $limit) {
            return false;
        }
        
        // Record this request
        $stmt = $db->prepare("
            INSERT INTO rate_limits (ip_address, created_at) VALUES (?, NOW())
        ");
        $stmt->execute([$ip]);
        
        return true;
    }
}

/**
 * CSRF Protection Class
 */
class CSRFProtection
{
    private $app;

    public function __construct()
    {
        $this->app = Application::getInstance();
    }

    public function generateToken(): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;
        $_SESSION['csrf_token_time'] = time();
        return $token;
    }

    public function validateToken(): bool
    {
        $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        $sessionToken = $_SESSION['csrf_token'] ?? null;
        
        if (!$token || !$sessionToken) {
            return false;
        }
        
        // Check token expiry
        $tokenTime = $_SESSION['csrf_token_time'] ?? 0;
        $expiry = $this->app->getConfig('csrf_token_expiry') ?? 3600;
        
        if (time() - $tokenTime > $expiry) {
            return false;
        }
        
        return hash_equals($sessionToken, $token);
    }
}


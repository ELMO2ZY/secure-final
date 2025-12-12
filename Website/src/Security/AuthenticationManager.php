<?php

namespace SecureFileShare\Security;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SecureFileShare\Core\Application;

class AuthenticationManager
{
    private $app;
    private $jwtSecret;
    private $jwtExpiry;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->jwtSecret = $this->app->getConfig('jwt_secret');
        $this->jwtExpiry = $this->app->getConfig('jwt_expiry');
    }

    /**
     * Generate JWT token for authenticated user
     */
    public function generateToken(array $userData): string
    {
        $payload = [
            'iss' => 'secure-file-share',
            'aud' => 'secure-file-share-users',
            'iat' => time(),
            'exp' => time() + $this->jwtExpiry,
            'user_id' => $userData['id'],
            'email' => $userData['email'],
            'role' => $userData['role'],
            'permissions' => $userData['permissions'] ?? [],
            'session_id' => $this->generateSessionId()
        ];

        return JWT::encode($payload, $this->jwtSecret, 'HS256');
    }

    /**
     * Validate JWT token and return user data
     */
    public function validateToken(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->jwtSecret, 'HS256'));
            
            // Check if token is expired
            if ($decoded->exp < time()) {
                return null;
            }

            // Verify session is still active
            if (!$this->isSessionActive($decoded->session_id)) {
                return null;
            }

            return [
                'user_id' => $decoded->user_id,
                'email' => $decoded->email,
                'role' => $decoded->role,
                'permissions' => $decoded->permissions ?? [],
                'session_id' => $decoded->session_id
            ];
        } catch (\Exception $e) {
            $this->app->getLogger()->warning('Token validation failed: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Authenticate user with email and password
     */
    public function authenticate(string $email, string $password): ?array
    {
        $db = $this->app->getDatabase();
        
        // Check login attempts
        if ($this->isAccountLocked($email)) {
            throw new \Exception('Account temporarily locked due to too many failed attempts');
        }

        $stmt = $db->prepare("
            SELECT id, email, password_hash, role, is_active, two_factor_enabled, 
                   failed_login_attempts, last_login_attempt
            FROM users 
            WHERE email = ? AND is_active = 1
        ");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            $this->recordFailedLogin($email);
            return null;
        }

        // Reset failed login attempts on successful login
        $this->resetFailedLoginAttempts($user['id']);

        // Update last login
        $this->updateLastLogin($user['id']);

        // Get user permissions
        $permissions = $this->getUserPermissions($user['id']);

        return [
            'id' => $user['id'],
            'email' => $user['email'],
            'role' => $user['role'],
            'permissions' => $permissions,
            'two_factor_enabled' => $user['two_factor_enabled']
        ];
    }

    /**
     * Verify 2FA code
     */
    public function verifyTwoFactor(string $email, string $code): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT two_factor_secret FROM users 
            WHERE email = ? AND is_active = 1
        ");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user || !$user['two_factor_secret']) {
            return false;
        }

        $google2fa = new \PragmaRX\Google2FA\Google2FA();
        return $google2fa->verifyKey($user['two_factor_secret'], $code);
    }

    /**
     * Check if user has specific permission
     */
    public function hasPermission(int $userId, string $permission): bool
    {
        $permissions = $this->getUserPermissions($userId);
        return in_array($permission, $permissions);
    }

    /**
     * Generate secure session ID
     */
    private function generateSessionId(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Check if session is still active
     */
    private function isSessionActive(string $sessionId): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT COUNT(*) FROM user_sessions 
            WHERE session_id = ? AND expires_at > NOW() AND is_active = 1
        ");
        $stmt->execute([$sessionId]);
        
        return $stmt->fetchColumn() > 0;
    }

    /**
     * Check if account is locked due to failed attempts
     */
    private function isAccountLocked(string $email): bool
    {
        $db = $this->app->getDatabase();
        $maxAttempts = $this->app->getConfig('max_login_attempts');
        
        $stmt = $db->prepare("
            SELECT failed_login_attempts, last_login_attempt 
            FROM users 
            WHERE email = ?
        ");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user) {
            return false;
        }

        // Check if attempts exceed limit and within lockout period
        if ($user['failed_login_attempts'] >= $maxAttempts) {
            $lockoutTime = strtotime($user['last_login_attempt']) + (15 * 60); // 15 minutes
            return time() < $lockoutTime;
        }

        return false;
    }

    /**
     * Record failed login attempt
     */
    private function recordFailedLogin(string $email): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                last_login_attempt = NOW()
            WHERE email = ?
        ");
        $stmt->execute([$email]);

        $this->app->getLogger()->warning("Failed login attempt for email: $email");
    }

    /**
     * Reset failed login attempts
     */
    private function resetFailedLoginAttempts(int $userId): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE users 
            SET failed_login_attempts = 0,
                last_login_attempt = NOW()
            WHERE id = ?
        ");
        $stmt->execute([$userId]);
    }

    /**
     * Update last login timestamp
     */
    private function updateLastLogin(int $userId): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE users 
            SET last_login = NOW()
            WHERE id = ?
        ");
        $stmt->execute([$userId]);
    }

    /**
     * Get user permissions based on role
     */
    private function getUserPermissions(int $userId): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT DISTINCT p.permission_name
            FROM users u
            JOIN role_permissions rp ON u.role = rp.role_name
            JOIN permissions p ON rp.permission_id = p.id
            WHERE u.id = ?
        ");
        $stmt->execute([$userId]);
        
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }
}


<?php

namespace SecureFileShare\API;

use SecureFileShare\Core\Application;
use SecureFileShare\Security\AuthenticationManager;
use SecureFileShare\Security\MonitoringManager;
use SecureFileShare\Security\SecurityMiddleware;

class AuthController
{
    private $app;
    private $authManager;
    private $monitoringManager;
    private $securityMiddleware;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->authManager = new AuthenticationManager();
        $this->monitoringManager = new MonitoringManager();
        $this->securityMiddleware = new SecurityMiddleware();
    }

    /**
     * Login endpoint
     */
    public function login(): void
    {
        try {
            // Apply security middleware
            if (!$this->securityMiddleware->handleRequest()) {
                return;
            }

            // Get input data
            $input = json_decode(file_get_contents('php://input'), true);
            
            // Validate input
            $validationErrors = $this->securityMiddleware->validateInput($input, [
                'email' => ['required' => true, 'type' => 'email'],
                'password' => ['required' => true, 'type' => 'string', 'min_length' => 6]
            ]);

            if (!empty($validationErrors)) {
                $this->sendErrorResponse(400, 'Validation failed: ' . implode(', ', $validationErrors));
                return;
            }

            // Authenticate user
            $user = $this->authManager->authenticate($input['email'], $input['password']);
            
            if (!$user) {
                $this->monitoringManager->logAuthentication($input['email'], 'login', false, [
                    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                $this->sendErrorResponse(401, 'Invalid credentials');
                return;
            }

            // Check if 2FA is enabled
            if ($user['two_factor_enabled']) {
                // Generate 2FA token
                $twoFactorToken = $this->generateTwoFactorToken($user['id']);
                
                $this->monitoringManager->logAuthentication($user['id'], 'login_2fa_required', true);
                
                $this->sendSuccessResponse([
                    'two_factor_required' => true,
                    'two_factor_token' => $twoFactorToken,
                    'message' => 'Two-factor authentication required'
                ]);
                return;
            }

            // Generate JWT token
            $token = $this->authManager->generateToken($user);
            
            // Store session
            $this->storeUserSession($user['id'], $token);

            // Log successful login
            $this->monitoringManager->logAuthentication($user['id'], 'login', true, [
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);

            $this->sendSuccessResponse([
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ],
                'message' => 'Login successful'
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('Login failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'Login failed');
        }
    }

    /**
     * Verify 2FA endpoint
     */
    public function verifyTwoFactor(): void
    {
        try {
            // Apply security middleware
            if (!$this->securityMiddleware->handleRequest()) {
                return;
            }

            // Get input data
            $input = json_decode(file_get_contents('php://input'), true);
            
            // Validate input
            $validationErrors = $this->securityMiddleware->validateInput($input, [
                'email' => ['required' => true, 'type' => 'email'],
                'code' => ['required' => true, 'type' => 'string', 'pattern' => '/^\d{6}$/'],
                'two_factor_token' => ['required' => true, 'type' => 'string']
            ]);

            if (!empty($validationErrors)) {
                $this->sendErrorResponse(400, 'Validation failed: ' . implode(', ', $validationErrors));
                return;
            }

            // Validate 2FA token
            if (!$this->validateTwoFactorToken($input['two_factor_token'], $input['email'])) {
                $this->sendErrorResponse(400, 'Invalid two-factor token');
                return;
            }

            // Verify 2FA code
            if (!$this->authManager->verifyTwoFactor($input['email'], $input['code'])) {
                $this->monitoringManager->logAuthentication($input['email'], '2fa_verification', false);
                $this->sendErrorResponse(401, 'Invalid 2FA code');
                return;
            }

            // Get user data
            $user = $this->getUserByEmail($input['email']);
            if (!$user) {
                $this->sendErrorResponse(401, 'User not found');
                return;
            }

            // Generate JWT token
            $token = $this->authManager->generateToken($user);
            
            // Store session
            $this->storeUserSession($user['id'], $token);

            // Log successful 2FA verification
            $this->monitoringManager->logAuthentication($user['id'], '2fa_verification', true);

            $this->sendSuccessResponse([
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ],
                'message' => 'Two-factor authentication successful'
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('2FA verification failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, '2FA verification failed');
        }
    }

    /**
     * Register endpoint
     */
    public function register(): void
    {
        try {
            // Apply security middleware
            if (!$this->securityMiddleware->handleRequest()) {
                return;
            }

            // Get input data
            $input = json_decode(file_get_contents('php://input'), true);
            
            // Validate input
            $validationErrors = $this->securityMiddleware->validateInput($input, [
                'email' => ['required' => true, 'type' => 'email'],
                'password' => ['required' => true, 'type' => 'string', 'min_length' => 8],
                'confirm_password' => ['required' => true, 'type' => 'string'],
                'first_name' => ['required' => true, 'type' => 'string', 'min_length' => 2],
                'last_name' => ['required' => true, 'type' => 'string', 'min_length' => 2]
            ]);

            if (!empty($validationErrors)) {
                $this->sendErrorResponse(400, 'Validation failed: ' . implode(', ', $validationErrors));
                return;
            }

            // Check password confirmation
            if ($input['password'] !== $input['confirm_password']) {
                $this->sendErrorResponse(400, 'Passwords do not match');
                return;
            }

            // Check if user already exists
            if ($this->userExists($input['email'])) {
                $this->sendErrorResponse(409, 'User already exists');
                return;
            }

            // Create user
            $userId = $this->createUser($input);

            // Log user registration
            $this->monitoringManager->logSystemEvent('user_registration', 
                "New user registered: {$input['email']}", [
                    'user_id' => $userId,
                    'email' => $input['email']
                ]);

            $this->sendSuccessResponse([
                'user_id' => $userId,
                'message' => 'User registered successfully'
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('Registration failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'Registration failed');
        }
    }

    /**
     * Logout endpoint
     */
    public function logout(): void
    {
        try {
            // Apply security middleware
            if (!$this->securityMiddleware->handleRequest()) {
                return;
            }

            // Authenticate user
            $user = $this->authenticateUser();
            if (!$user) {
                $this->sendErrorResponse(401, 'Authentication required');
                return;
            }

            // Invalidate session
            $this->invalidateUserSession($user['session_id']);

            // Log logout
            $this->monitoringManager->logAuthentication($user['user_id'], 'logout', true);

            $this->sendSuccessResponse(['message' => 'Logout successful']);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('Logout failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'Logout failed');
        }
    }

    /**
     * Refresh token endpoint
     */
    public function refreshToken(): void
    {
        try {
            // Apply security middleware
            if (!$this->securityMiddleware->handleRequest()) {
                return;
            }

            // Authenticate user
            $user = $this->authenticateUser();
            if (!$user) {
                $this->sendErrorResponse(401, 'Authentication required');
                return;
            }

            // Generate new token
            $newToken = $this->authManager->generateToken($user);
            
            // Update session
            $this->updateUserSession($user['session_id'], $newToken);

            $this->sendSuccessResponse([
                'token' => $newToken,
                'message' => 'Token refreshed successfully'
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('Token refresh failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'Token refresh failed');
        }
    }

    /**
     * Enable 2FA endpoint
     */
    public function enableTwoFactor(): void
    {
        try {
            // Apply security middleware
            if (!$this->securityMiddleware->handleRequest()) {
                return;
            }

            // Authenticate user
            $user = $this->authenticateUser();
            if (!$user) {
                $this->sendErrorResponse(401, 'Authentication required');
                return;
            }

            // Generate 2FA secret
            $google2fa = new \PragmaRX\Google2FA\Google2FA();
            $secret = $google2fa->generateSecretKey();

            // Store secret in database
            $this->storeTwoFactorSecret($user['user_id'], $secret);

            // Generate QR code URL
            $qrCodeUrl = $google2fa->getQRCodeUrl(
                'Secure File Share',
                $user['email'],
                $secret
            );

            $this->sendSuccessResponse([
                'secret' => $secret,
                'qr_code_url' => $qrCodeUrl,
                'message' => '2FA setup successful'
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('2FA setup failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, '2FA setup failed');
        }
    }

    /**
     * Authenticate user from request
     */
    private function authenticateUser(): ?array
    {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return null;
        }

        $token = $matches[1];
        return $this->authManager->validateToken($token);
    }

    /**
     * Generate 2FA token
     */
    private function generateTwoFactorToken(string $userId): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION['two_factor_token_' . $userId] = $token;
        $_SESSION['two_factor_token_time_' . $userId] = time();
        return $token;
    }

    /**
     * Validate 2FA token
     */
    private function validateTwoFactorToken(string $token, string $email): bool
    {
        $user = $this->getUserByEmail($email);
        if (!$user) {
            return false;
        }

        $sessionToken = $_SESSION['two_factor_token_' . $user['id']] ?? null;
        $tokenTime = $_SESSION['two_factor_token_time_' . $user['id']] ?? 0;

        // Check if token is expired (5 minutes)
        if (time() - $tokenTime > 300) {
            return false;
        }

        return hash_equals($sessionToken, $token);
    }

    /**
     * Get user by email
     */
    private function getUserByEmail(string $email): ?array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT id, email, role, is_active, two_factor_enabled
            FROM users 
            WHERE email = ? AND is_active = 1
        ");
        $stmt->execute([$email]);
        
        return $stmt->fetch();
    }

    /**
     * Check if user exists
     */
    private function userExists(string $email): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
        $stmt->execute([$email]);
        
        return $stmt->fetchColumn() > 0;
    }

    /**
     * Create new user
     */
    private function createUser(array $input): string
    {
        $db = $this->app->getDatabase();
        
        $userId = bin2hex(random_bytes(16));
        $passwordHash = password_hash($input['password'], PASSWORD_DEFAULT);
        
        $stmt = $db->prepare("
            INSERT INTO users (
                id, email, password_hash, first_name, last_name, 
                role, is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, 'user', 1, NOW())
        ");
        
        $stmt->execute([
            $userId,
            $input['email'],
            $passwordHash,
            $input['first_name'],
            $input['last_name']
        ]);
        
        return $userId;
    }

    /**
     * Store user session
     */
    private function storeUserSession(string $userId, string $token): void
    {
        $db = $this->app->getDatabase();
        
        // Extract session ID from token
        $decoded = \Firebase\JWT\JWT::decode($token, new \Firebase\JWT\Key($this->app->getConfig('jwt_secret'), 'HS256'));
        $sessionId = $decoded->session_id;
        
        $stmt = $db->prepare("
            INSERT INTO user_sessions (
                session_id, user_id, token_hash, expires_at, is_active, created_at
            ) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), 1, NOW())
        ");
        
        $tokenHash = hash('sha256', $token);
        $expiry = $this->app->getConfig('jwt_expiry');
        
        $stmt->execute([$sessionId, $userId, $tokenHash, $expiry]);
    }

    /**
     * Invalidate user session
     */
    private function invalidateUserSession(string $sessionId): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE user_sessions 
            SET is_active = 0, expires_at = NOW()
            WHERE session_id = ?
        ");
        $stmt->execute([$sessionId]);
    }

    /**
     * Update user session
     */
    private function updateUserSession(string $sessionId, string $newToken): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE user_sessions 
            SET token_hash = ?, expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND)
            WHERE session_id = ?
        ");
        
        $tokenHash = hash('sha256', $newToken);
        $expiry = $this->app->getConfig('jwt_expiry');
        
        $stmt->execute([$tokenHash, $expiry, $sessionId]);
    }

    /**
     * Store 2FA secret
     */
    private function storeTwoFactorSecret(string $userId, string $secret): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE users 
            SET two_factor_secret = ?, two_factor_enabled = 1
            WHERE id = ?
        ");
        $stmt->execute([$secret, $userId]);
    }

    /**
     * Send success response
     */
    private function sendSuccessResponse(array $data): void
    {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => true,
            'data' => $data,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    }

    /**
     * Send error response
     */
    private function sendErrorResponse(int $code, string $message): void
    {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => $message,
            'code' => $code,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    }
}


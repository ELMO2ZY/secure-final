<?php
/**
 * Secure File Sharing API - Database-Backed Implementation
 * No hardcoded values - All data from database and environment variables
 */

session_start();
require_once 'config.php';

// Get database connection
function getDB() {
    return getDatabase();
}

// Generate JWT token
function generateToken($userData, $permissions) {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64_encode(json_encode([
        'user_id' => $userData['id'],
        'email' => $userData['email'],
        'role' => $userData['role'],
        'permissions' => $permissions,
        'exp' => time() + JWT_EXPIRY
    ]));
    $signature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, JWT_SECRET, true));
    return $header . '.' . $payload . '.' . $signature;
}

// Validate JWT token
function validateToken($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;

    $header = $parts[0];
    $payload = $parts[1];
    $signature = $parts[2];

    $expectedSignature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, JWT_SECRET, true));
    if (!hash_equals($signature, $expectedSignature)) return false;

    $payloadData = json_decode(base64_decode($payload), true);
    if ($payloadData['exp'] < time()) return false;

    return $payloadData;
}

// Get user permissions from database
function getUserPermissions($userId, $role) {
    $db = getDB();
    
    // Admin has all permissions
    if ($role === 'admin') {
        return ['all'];
    }
    
    // Get permissions from database
    try {
        $stmt = $db->prepare("
            SELECT DISTINCT p.permission_name
            FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.role_name = ?
        ");
        $stmt->execute([$role]);
        $permissions = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        return $permissions ?: [];
    } catch (Exception $e) {
        error_log("Error getting permissions: " . $e->getMessage());
        // Return default permissions based on role
        if ($role === 'user') {
            return ['file.upload', 'file.download', 'file.share'];
        } elseif ($role === 'viewer') {
            return ['file.download'];
        }
        return [];
    }
}

// Check if user has permission
function hasPermission($userPermissions, $requiredPermission) {
    return in_array('all', $userPermissions) || in_array($requiredPermission, $userPermissions);
}

// Encrypt data using AES-256
function encryptData($data, $key = null) {
    $key = $key ?: ENCRYPTION_KEY;
    if (strlen($key) < 32) {
        $key = hash('sha256', $key);
    }
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', substr($key, 0, 32), 0, $iv);
    return base64_encode($iv . $encrypted);
}

// Decrypt data
function decryptData($encryptedData, $key = null) {
    $key = $key ?: ENCRYPTION_KEY;
    if (strlen($key) < 32) {
        $key = hash('sha256', $key);
    }
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', substr($key, 0, 32), 0, $iv);
}

// Log audit event
function logAuditEvent($eventType, $userId, $action, $success, $description, $metadata = []) {
    $db = getDB();
    $stmt = $db->prepare("
        INSERT INTO audit_logs (event_type, user_id, action, success, description, ip_address, user_agent, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");
    $stmt->execute([
        $eventType,
        $userId,
        $action,
        $success ? 1 : 0,
        $description,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        json_encode($metadata)
    ]);
}

// Handle API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    switch ($_POST['action']) {
        case 'login':
            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';

            if (empty($email) || empty($password)) {
                echo json_encode(['success' => false, 'message' => 'Email and password are required']);
                exit;
            }

            try {
                $db = getDB();
                
                // Get user from database
                $stmt = $db->prepare("
                    SELECT id, email, password_hash, role, is_active, two_factor_enabled,
                           failed_login_attempts, last_login_attempt, first_name, last_name
                    FROM users 
                    WHERE email = ? AND is_active = 1
                ");
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                if (!$user) {
                    logAuditEvent('authentication', null, 'login', false, "Failed login attempt for email: $email");
                    echo json_encode(['success' => false, 'message' => 'Invalid email or password']);
                    exit;
                }

                // Check if account is locked
                $maxAttempts = MAX_LOGIN_ATTEMPTS;
                if ($user['failed_login_attempts'] >= $maxAttempts) {
                    $lockoutTime = strtotime($user['last_login_attempt']) + (15 * 60); // 15 minutes
                    if (time() < $lockoutTime) {
                        echo json_encode(['success' => false, 'message' => 'Account temporarily locked due to too many failed attempts']);
                        exit;
                    }
                }

                // Verify password
                if (!password_verify($password, $user['password_hash'])) {
                    // Record failed attempt
                    $stmt = $db->prepare("
                        UPDATE users 
                        SET failed_login_attempts = failed_login_attempts + 1,
                            last_login_attempt = NOW()
                        WHERE email = ?
                    ");
                    $stmt->execute([$email]);
                    
                    logAuditEvent('authentication', $user['id'], 'login', false, "Invalid password for email: $email");
                    echo json_encode(['success' => false, 'message' => 'Invalid email or password']);
                    exit;
                }

                // Reset failed login attempts
                $stmt = $db->prepare("
                    UPDATE users 
                    SET failed_login_attempts = 0,
                        last_login = NOW(),
                        last_login_attempt = NOW()
                    WHERE id = ?
                ");
                $stmt->execute([$user['id']]);

                // Get user permissions
                $permissions = getUserPermissions($user['id'], $user['role']);

                // Generate token
                $token = generateToken($user, $permissions);

                // Store session in database
                $sessionId = bin2hex(random_bytes(32));
                $stmt = $db->prepare("
                    INSERT INTO user_sessions (session_id, user_id, token_hash, expires_at, created_at)
                    VALUES (?, ?, ?, FROM_UNIXTIME(?), NOW())
                ");
                $stmt->execute([
                    $sessionId,
                    $user['id'],
                    hash('sha256', $token),
                    time() + JWT_EXPIRY
                ]);

                $_SESSION['user_token'] = $token;
                $_SESSION['user_id'] = $user['id'];

                logAuditEvent('authentication', $user['id'], 'login', true, "Successful login for email: $email");

                echo json_encode([
                    'success' => true,
                    'token' => $token,
                    'user' => [
                        'id' => $user['id'],
                        'name' => $user['first_name'] . ' ' . $user['last_name'],
                        'email' => $user['email'],
                        'role' => $user['role'],
                        'permissions' => $permissions,
                        'two_factor_enabled' => (bool)$user['two_factor_enabled']
                    ],
                    'message' => 'Login successful'
                ]);
            } catch (Exception $e) {
                error_log("Login error: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'Login failed. Please try again.']);
            }
            exit;

        case 'upload':
            $token = $_POST['token'] ?? '';
            $userData = validateToken($token);

            if (!$userData) {
                echo json_encode(['success' => false, 'message' => 'Invalid or expired token']);
                exit;
            }

            $permissions = $userData['permissions'] ?? [];
            if (!hasPermission($permissions, 'file.upload')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }

            if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
                try {
                    $db = getDB();
                    $file = $_FILES['file'];
                    
                    // Validate file size
                    if ($file['size'] > MAX_FILE_SIZE) {
                        echo json_encode(['success' => false, 'message' => 'File size exceeds maximum allowed size']);
                        exit;
                    }

                    // Read file content
                    $fileContent = file_get_contents($file['tmp_name']);
                    $fileHash = hash('sha256', $fileContent);
                    
                    // Encrypt file content
                    $encryptedContent = encryptData($fileContent);
                    
                    // Generate file ID
                    $fileId = bin2hex(random_bytes(16));
                    $encryptedFileName = $fileId . '.enc';
                    $encryptedPath = ENCRYPTED_PATH . $encryptedFileName;
                    
                    // Save encrypted file
                    file_put_contents($encryptedPath, $encryptedContent);
                    
                    // Store in database
                    $expiryHours = intval($_POST['expiry_hours'] ?? 24);
                    $expiresAt = date('Y-m-d H:i:s', time() + ($expiryHours * 3600));
                    
                    $stmt = $db->prepare("
                        INSERT INTO files (
                            file_id, user_id, original_name, encrypted_name, file_size,
                            encrypted_size, mime_type, file_hash, encrypted_file_key,
                            expires_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
                    ");
                    $stmt->execute([
                        $fileId,
                        $userData['user_id'],
                        $file['name'],
                        $encryptedFileName,
                        $file['size'],
                        strlen($encryptedContent),
                        $file['type'],
                        $fileHash,
                        encryptData($fileId . '_key'), // Encrypted file key
                        $expiresAt
                    ]);

                    logAuditEvent('file', $userData['user_id'], 'upload', true, "File uploaded: {$file['name']}", [
                        'file_id' => $fileId,
                        'file_size' => $file['size']
                    ]);

                    echo json_encode([
                        'success' => true,
                        'file_id' => $fileId,
                        'message' => 'File uploaded and encrypted successfully',
                        'file_info' => [
                            'name' => $file['name'],
                            'size' => $file['size'],
                            'encrypted' => true,
                            'expires_at' => $expiresAt
                        ]
                    ]);
                } catch (Exception $e) {
                    error_log("Upload error: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => 'File upload failed']);
                }
            } else {
                echo json_encode(['success' => false, 'message' => 'File upload failed']);
            }
            exit;

        case 'download':
            $token = $_POST['token'] ?? '';
            $fileId = $_POST['file_id'] ?? '';
            $userData = validateToken($token);

            if (!$userData) {
                echo json_encode(['success' => false, 'message' => 'Invalid or expired token']);
                exit;
            }

            $permissions = $userData['permissions'] ?? [];
            if (!hasPermission($permissions, 'file.download')) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }

            try {
                $db = getDB();
                
                $stmt = $db->prepare("
                    SELECT f.*, 
                           CASE WHEN f.user_id = ? OR ? = 'admin' THEN 1 ELSE 0 END as can_access
                    FROM files f
                    WHERE f.file_id = ? AND f.is_deleted = 0
                ");
                $stmt->execute([$userData['user_id'], $userData['role'], $fileId]);
                $file = $stmt->fetch();

                if (!$file || !$file['can_access']) {
                    echo json_encode(['success' => false, 'message' => 'File not found or access denied']);
                    exit;
                }

                if ($file['expires_at'] && strtotime($file['expires_at']) < time()) {
                    echo json_encode(['success' => false, 'message' => 'File has expired']);
                    exit;
                }

                // Read and decrypt file
                $encryptedPath = ENCRYPTED_PATH . $file['encrypted_name'];
                if (!file_exists($encryptedPath)) {
                    echo json_encode(['success' => false, 'message' => 'File not found on server']);
                    exit;
                }

                $encryptedContent = file_get_contents($encryptedPath);
                $decryptedContent = decryptData($encryptedContent);

                logAuditEvent('file', $userData['user_id'], 'download', true, "File downloaded: {$file['original_name']}", [
                    'file_id' => $fileId
                ]);

                echo json_encode([
                    'success' => true,
                    'file_name' => $file['original_name'],
                    'file_size' => $file['file_size'],
                    'mime_type' => $file['mime_type'],
                    'content' => base64_encode($decryptedContent),
                    'message' => 'File decrypted successfully'
                ]);
            } catch (Exception $e) {
                error_log("Download error: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'File download failed']);
            }
            exit;

        case 'list_files':
            $token = $_POST['token'] ?? '';
            $userData = validateToken($token);

            if (!$userData) {
                echo json_encode(['success' => false, 'message' => 'Invalid or expired token']);
                exit;
            }

            try {
                $db = getDB();
                
                // Get user's files or all files if admin
                if ($userData['role'] === 'admin' || hasPermission($userData['permissions'] ?? [], 'file.view_all')) {
                    $stmt = $db->prepare("
                        SELECT f.file_id, f.original_name, f.file_size, f.mime_type,
                               f.expires_at, f.created_at, u.email as uploaded_by_email
                        FROM files f
                        JOIN users u ON f.user_id = u.id
                        WHERE f.is_deleted = 0
                        ORDER BY f.created_at DESC
                    ");
                    $stmt->execute();
                } else {
                    $stmt = $db->prepare("
                        SELECT file_id, original_name, file_size, mime_type,
                               expires_at, created_at
                        FROM files
                        WHERE user_id = ? AND is_deleted = 0
                        ORDER BY created_at DESC
                    ");
                    $stmt->execute([$userData['user_id']]);
                }
                
                $files = $stmt->fetchAll();
                
                // Format files
                $userFiles = array_map(function($file) {
                    $isExpired = $file['expires_at'] && strtotime($file['expires_at']) < time();
                    return [
                        'file_id' => $file['file_id'],
                        'name' => $file['original_name'],
                        'size' => intval($file['file_size']),
                        'mime_type' => $file['mime_type'],
                        'uploaded_at' => $file['created_at'],
                        'expires_at' => $file['expires_at'],
                        'encrypted' => true,
                        'expired' => $isExpired,
                        'uploaded_by' => $file['uploaded_by_email'] ?? null
                    ];
                }, $files);

                echo json_encode([
                    'success' => true,
                    'files' => $userFiles,
                    'message' => 'Files retrieved successfully'
                ]);
            } catch (Exception $e) {
                error_log("List files error: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'Failed to retrieve files']);
            }
            exit;

        case 'signup':
            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $firstName = trim($_POST['first_name'] ?? '');
            $lastName = trim($_POST['last_name'] ?? '');

            if (empty($email) || empty($password) || empty($firstName) || empty($lastName)) {
                echo json_encode(['success' => false, 'message' => 'All fields are required']);
                exit;
            }

            // Validate email
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                echo json_encode(['success' => false, 'message' => 'Invalid email address']);
                exit;
            }

            // Validate password strength
            if (strlen($password) < 6) {
                echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters long']);
                exit;
            }

            try {
                $db = getDB();
                
                // Check if user already exists
                $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    echo json_encode(['success' => false, 'message' => 'Email already registered']);
                    exit;
                }

                // Generate user ID
                $userId = bin2hex(random_bytes(16));
                
                // Hash password
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                
                // Insert new user (default role is 'user')
                $stmt = $db->prepare("
                    INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, 'user', 1, NOW())
                ");
                $stmt->execute([$userId, $email, $passwordHash, $firstName, $lastName]);

                logAuditEvent('user_management', $userId, 'signup', true, "New user registered: $email");

                echo json_encode([
                    'success' => true,
                    'message' => 'Account created successfully. You can now login.',
                    'user_id' => $userId
                ]);
            } catch (Exception $e) {
                error_log("Signup error: " . $e->getMessage());
                echo json_encode(['success' => false, 'message' => 'Registration failed. Please try again.']);
            }
            exit;

        case 'logout':
            $token = $_POST['token'] ?? '';
            $userData = validateToken($token);

            if ($userData) {
                try {
                    $db = getDB();
                    $stmt = $db->prepare("
                        UPDATE user_sessions 
                        SET is_active = 0 
                        WHERE user_id = ? AND token_hash = ?
                    ");
                    $stmt->execute([$userData['user_id'], hash('sha256', $token)]);
                } catch (Exception $e) {
                    error_log("Logout error: " . $e->getMessage());
                }
            }

            session_destroy();
            echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
            exit;

        default:
            echo json_encode(['success' => false, 'message' => 'Invalid action']);
            exit;
    }
} else {
    echo json_encode([
        'success' => false, 
        'message' => 'Invalid request method or missing action'
    ]);
}
?>


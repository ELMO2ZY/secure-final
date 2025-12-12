<?php
session_start();

// Simple JWT-like token system
function generateToken($user) {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64_encode(json_encode([
        'user_id' => $user['id'],
        'email' => $user['email'],
        'role' => $user['role'],
        'permissions' => $user['permissions'],
        'exp' => time() + (defined('JWT_EXPIRY') ? JWT_EXPIRY : 3600)
    ]));
    $secret = defined('JWT_SECRET') ? JWT_SECRET : 'secure_jwt_secret_key';
    $signature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, $secret, true));
    return $header . '.' . $payload . '.' . $signature;
}

function validateToken($token) {
    if (empty($token)) {
        return false;
    }
    
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    $header = $parts[0];
    $payload = $parts[1];
    $signature = $parts[2];

    // Use the same secret as generateToken
    $secret = defined('JWT_SECRET') ? JWT_SECRET : 'secure_jwt_secret_key';
    $expectedSignature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, $secret, true));
    
    if (!hash_equals($signature, $expectedSignature)) {
        return false;
    }

    $payloadData = json_decode(base64_decode($payload), true);
    if (!$payloadData) {
        return false;
    }
    
    // Check expiration
    if (isset($payloadData['exp']) && $payloadData['exp'] < time()) {
        return false;
    }

    return $payloadData;
}

// Simple encryption functions
function encryptData($data, $key) {
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptData($encryptedData, $key) {
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
}

// Log activity to session
function logActivity($eventType, $action, $fileId = null, $fileName = null, $userId = null, $success = true, $description = null, $riskLevel = 'low') {
    if (!isset($_SESSION['activity_logs'])) {
        $_SESSION['activity_logs'] = [];
    }

    // Get user email from token if available
    $userEmail = 'Unknown User';
    if ($userId) {
        // Try to get user email from token
        $token = $_SESSION['user_token'] ?? '';
        if ($token) {
            $user = validateToken($token);
            if ($user && isset($user['email'])) {
                $userEmail = $user['email'];
            }
        }
    }

    $log = [
        'id' => uniqid('log_', true),
        'event_type' => $eventType,
        'action' => $action,
        'file_id' => $fileId,
        'file_name' => $fileName ?? 'Unknown File',
        'user_id' => $userId,
        'user_email' => $userEmail,
        'success' => $success,
        'description' => $description,
        'risk_level' => $riskLevel,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'session_id' => session_id(),
        'created_at' => time()
    ];

    // Add to beginning of array (newest first)
    array_unshift($_SESSION['activity_logs'], $log);

    // Keep only last 1000 logs to prevent memory issues
    if (count($_SESSION['activity_logs']) > 1000) {
        $_SESSION['activity_logs'] = array_slice($_SESSION['activity_logs'], 0, 1000);
    }
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

            // Hardcoded users (no database)
            $users = [
                'admin@securefileshare.com' => [
                    'id' => 'admin_001',
                    'password' => 'admin123',
                    'role' => 'admin',
                    'name' => 'Mohamed Loai',
                    'permissions' => ['all'],
                    'two_factor_enabled' => true,
                    'secret' => 'JBSWY3DPEHPK3PXP'
                ],
                'user@securefileshare.com' => [
                    'id' => 'user_001',
                    'password' => 'user123',
                    'role' => 'user',
                    'name' => 'Test User',
                    'permissions' => ['file.upload', 'file.download', 'file.share'],
                    'two_factor_enabled' => false,
                    'secret' => null
                ],
                'viewer@securefileshare.com' => [
                    'id' => 'viewer_001',
                    'password' => 'viewer123',
                    'role' => 'viewer',
                    'name' => 'Test Viewer',
                    'permissions' => ['file.download'],
                    'two_factor_enabled' => false,
                    'secret' => null
                ]
            ];

            if (isset($users[$email]) && $users[$email]['password'] === $password) {
                $user = $users[$email];
                // Add email to user array for token generation
                $user['email'] = $email;
                $token = generateToken($user);
                $_SESSION['user_token'] = $token;
                $_SESSION['user_id'] = $user['id'];

                // Log successful login
                logActivity('authentication', 'login', null, null, $user['id'], true, "User logged in successfully: {$email}", 'low');

                echo json_encode([
                    'success' => true,
                    'token' => $token,
                    'user' => [
                        'id' => $user['id'],
                        'name' => $user['name'],
                        'email' => $email,
                        'role' => $user['role'],
                        'permissions' => $user['permissions'],
                        'two_factor_enabled' => $user['two_factor_enabled']
                    ],
                    'message' => 'Login successful'
                ]);
            } else {
                // Log failed login attempt
                logActivity('authentication', 'login', null, null, null, false, "Failed login attempt for: {$email}", 'high');
                
                echo json_encode(['success' => false, 'message' => 'Invalid email or password. Please try again.']);
            }
            exit;

        case 'upload':
            $token = $_POST['token'] ?? '';
            $user = validateToken($token);

            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'Invalid token']);
                exit;
            }

            if (!in_array('file.upload', $user['permissions']) && !in_array('all', $user['permissions'])) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }

            if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
                $fileContent = file_get_contents($_FILES['file']['tmp_name']);
                $encryptedContent = encryptData($fileContent, 'file_encryption_key_32_chars');

                $fileId = uniqid('file_', true);
                $fileName = $_FILES['file']['name'];

                // Get expiry hours from request, default to 24 hours
                $expiryHours = isset($_POST['expiry_hours']) ? intval($_POST['expiry_hours']) : 24;
                
                // Store encrypted file info
                $_SESSION['files'][$fileId] = [
                    'name' => $fileName,
                    'size' => $_FILES['file']['size'],
                    'encrypted_content' => $encryptedContent,
                    'uploaded_by' => $user['user_id'],
                    'uploaded_at' => time(),
                    'expires_at' => time() + ($expiryHours * 3600) // Convert hours to seconds
                ];

                // Log upload activity
                logActivity('file_upload', 'upload', $fileId, $fileName, $user['user_id'], true, "File uploaded: {$fileName}", 'low');

                echo json_encode([
                    'success' => true,
                    'file_id' => $fileId,
                    'message' => 'File uploaded and encrypted successfully',
                    'file_info' => [
                        'name' => $fileName,
                        'size' => $_FILES['file']['size'],
                        'encrypted' => true
                    ]
                ]);
            } else {
                echo json_encode(['success' => false, 'message' => 'File upload failed']);
            }
            exit;

        case 'download':
            $token = $_POST['token'] ?? '';
            $fileId = $_POST['file_id'] ?? '';
            $user = validateToken($token);

            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'Invalid token']);
                exit;
            }

            if (!isset($_SESSION['files'][$fileId])) {
                // Log file not found
                logActivity('file_access', 'download', $fileId, 'Unknown File', $user['user_id'], false, "File not found: {$fileId}", 'medium');
                echo json_encode(['success' => false, 'message' => 'File not found']);
                exit;
            }

            $file = $_SESSION['files'][$fileId];

            if ($file['expires_at'] < time()) {
                // Log expired file access
                logActivity('file_access', 'download', $fileId, $file['name'], $user['user_id'], false, "File expired: {$file['name']}", 'high');
                echo json_encode(['success' => false, 'message' => 'File has expired']);
                exit;
            }

            if (!in_array('file.download', $user['permissions']) && !in_array('all', $user['permissions'])) {
                // Log access denied
                logActivity('access_denied', 'download', $fileId, $file['name'], $user['user_id'], false, "Access denied: Insufficient permissions to download {$file['name']}", 'high');
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }

            // Log successful download
            logActivity('file_download', 'download', $fileId, $file['name'], $user['user_id'], true, "File downloaded: {$file['name']}", 'low');

            // Check if user wants encrypted version
            $getEncrypted = isset($_POST['get_encrypted']) && $_POST['get_encrypted'] === 'true';
            
            if ($getEncrypted) {
                // Return encrypted content with original extension so it can be opened in text editor
                echo json_encode([
                    'success' => true,
                    'file_name' => $file['name'], // Keep original extension
                    'file_size' => strlen($file['encrypted_content']),
                    'content' => base64_encode($file['encrypted_content']),
                    'message' => 'Encrypted file retrieved successfully',
                    'is_encrypted' => true
                ]);
            } else {
                // Return decrypted content (normal download)
                $decryptedContent = decryptData($file['encrypted_content'], 'file_encryption_key_32_chars');
                
                echo json_encode([
                    'success' => true,
                    'file_name' => $file['name'],
                    'file_size' => $file['size'],
                    'content' => base64_encode($decryptedContent),
                    'message' => 'File decrypted successfully',
                    'is_encrypted' => false
                ]);
            }
            exit;

        case 'list_files':
            $token = $_POST['token'] ?? '';
            $user = validateToken($token);

            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'Invalid token']);
                exit;
            }

            $userFiles = [];
            if (isset($_SESSION['files'])) {
                foreach ($_SESSION['files'] as $fileId => $file) {
                    if ($file['uploaded_by'] === $user['user_id'] || in_array('all', $user['permissions'])) {
                        $userFiles[] = [
                            'file_id' => $fileId,
                            'name' => $file['name'],
                            'size' => $file['size'],
                            'uploaded_at' => date('Y-m-d H:i:s', $file['uploaded_at']),
                            'expires_at' => date('Y-m-d H:i:s', $file['expires_at']),
                            'encrypted' => true
                        ];
                    }
                }
            }

            echo json_encode([
                'success' => true,
                'files' => $userFiles,
                'message' => 'Files retrieved successfully'
            ]);
            exit;

        case 'delete_file':
            $token = $_POST['token'] ?? '';
            $fileId = $_POST['file_id'] ?? '';
            $user = validateToken($token);

            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'Invalid token']);
                exit;
            }

            // Check if user is admin or owns the file
            if (!in_array('all', $user['permissions'])) {
                if (!isset($_SESSION['files'][$fileId]) || $_SESSION['files'][$fileId]['uploaded_by'] !== $user['user_id']) {
                    echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                    exit;
                }
            }

            if (!isset($_SESSION['files'][$fileId])) {
                echo json_encode(['success' => false, 'message' => 'File not found']);
                exit;
            }

            // Log file deletion
            $fileName = $_SESSION['files'][$fileId]['name'] ?? 'Unknown File';
            logActivity('file_delete', 'delete', $fileId, $fileName, $user['user_id'], true, "File deleted: {$fileName}", 'medium');

            // Delete the file
            unset($_SESSION['files'][$fileId]);

            echo json_encode([
                'success' => true,
                'message' => 'File deleted successfully'
            ]);
            exit;

        case 'update_file':
            $token = $_POST['token'] ?? '';
            $fileId = $_POST['file_id'] ?? '';
            $user = validateToken($token);

            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'Invalid token']);
                exit;
            }

            // Check if user is admin or owns the file
            if (!in_array('all', $user['permissions'])) {
                if (!isset($_SESSION['files'][$fileId]) || $_SESSION['files'][$fileId]['uploaded_by'] !== $user['user_id']) {
                    echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                    exit;
                }
            }

            if (!isset($_SESSION['files'][$fileId])) {
                echo json_encode(['success' => false, 'message' => 'File not found']);
                exit;
            }

            // Update file properties
            if (isset($_POST['new_name'])) {
                $_SESSION['files'][$fileId]['name'] = $_POST['new_name'];
            }
            if (isset($_POST['expiry_hours'])) {
                $expiryHours = intval($_POST['expiry_hours']);
                $_SESSION['files'][$fileId]['expires_at'] = time() + ($expiryHours * 3600);
            }

            echo json_encode([
                'success' => true,
                'message' => 'File updated successfully',
                'file_info' => [
                    'name' => $_SESSION['files'][$fileId]['name'],
                    'expires_at' => date('Y-m-d H:i:s', $_SESSION['files'][$fileId]['expires_at'])
                ]
            ]);
            exit;

        case 'logout':
            session_destroy();
            echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
            exit;

        case 'get_activity_logs':
            $token = $_POST['token'] ?? '';
            $user = validateToken($token);

            if (!$user) {
                echo json_encode(['success' => false, 'message' => 'Invalid token']);
                exit;
            }

            // Initialize activity logs in session if not exists
            if (!isset($_SESSION['activity_logs'])) {
                $_SESSION['activity_logs'] = [];
            }

            // Get filters
            $riskLevel = $_POST['risk_level'] ?? 'all';
            $actionType = $_POST['action_type'] ?? 'all';
            $search = $_POST['search'] ?? '';
            $limit = isset($_POST['limit']) ? intval($_POST['limit']) : 50;

            // Get all activity logs
            $allLogs = $_SESSION['activity_logs'] ?? [];

            // Filter by user (non-admin users only see their own logs)
            if (!in_array('all', $user['permissions'])) {
                $allLogs = array_filter($allLogs, function($log) use ($user) {
                    return isset($log['user_id']) && $log['user_id'] === $user['user_id'];
                });
            }

            // Apply filters
            $filteredLogs = [];
            foreach ($allLogs as $log) {
                // Risk level filter
                if ($riskLevel !== 'all') {
                    $logRiskLevel = $log['risk_level'] ?? 'low';
                    if ($logRiskLevel !== $riskLevel) {
                        continue;
                    }
                }

                // Action type filter
                if ($actionType !== 'all') {
                    $logAction = strtolower($log['action'] ?? '');
                    if ($logAction !== strtolower($actionType)) {
                        continue;
                    }
                }

                // Search filter
                if (!empty($search)) {
                    $searchLower = strtolower($search);
                    $fileName = strtolower($log['file_name'] ?? '');
                    $userEmail = strtolower($log['user_email'] ?? '');
                    $description = strtolower($log['description'] ?? '');
                    $action = strtolower($log['action'] ?? '');
                    
                    if (strpos($fileName, $searchLower) === false &&
                        strpos($userEmail, $searchLower) === false &&
                        strpos($description, $searchLower) === false &&
                        strpos($action, $searchLower) === false) {
                        continue;
                    }
                }

                $filteredLogs[] = $log;
            }

            // Sort by created_at (newest first)
            usort($filteredLogs, function($a, $b) {
                return ($b['created_at'] ?? 0) - ($a['created_at'] ?? 0);
            });

            // Format logs for frontend (convert timestamps to date strings)
            $formattedLogs = [];
            foreach (array_slice($filteredLogs, 0, $limit) as $log) {
                $log['created_at'] = isset($log['created_at']) && is_numeric($log['created_at']) 
                    ? date('Y-m-d H:i:s', $log['created_at']) 
                    : ($log['created_at'] ?? date('Y-m-d H:i:s'));
                $formattedLogs[] = $log;
            }
            $logs = $formattedLogs;

            // Calculate statistics from all logs (not filtered)
            $stats = [
                'total_events' => count($allLogs),
                'downloads' => 0,
                'access_denied' => 0,
                'high_risk' => 0
            ];

            foreach ($allLogs as $log) {
                $action = strtolower($log['action'] ?? '');
                $riskLevel = $log['risk_level'] ?? 'low';
                $success = $log['success'] ?? true;

                if ($action === 'download') {
                    $stats['downloads']++;
                }
                if (!$success || $riskLevel === 'high') {
                    $stats['access_denied']++;
                }
                if ($riskLevel === 'high') {
                    $stats['high_risk']++;
                }
            }

            echo json_encode([
                'success' => true,
                'logs' => $logs,
                'stats' => $stats,
                'message' => 'Activity logs retrieved successfully'
            ]);
            exit;

        default:
            echo json_encode(['success' => false, 'message' => 'Invalid action']);
            exit;
    }
} else {
    // Log what we received for debugging
    error_log('API Request - Method: ' . $_SERVER['REQUEST_METHOD'] . ', POST data: ' . print_r($_POST, true));
    echo json_encode([
        'success' => false, 
        'message' => 'Invalid request method or missing action',
        'debug' => [
            'method' => $_SERVER['REQUEST_METHOD'],
            'has_post' => !empty($_POST),
            'post_keys' => array_keys($_POST)
        ]
    ]);
}
?>



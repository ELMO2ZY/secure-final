<?php
session_start();

// Hardcoded user data for demo
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

// Simple JWT-like token system
function generateToken($user) {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64_encode(json_encode([
        'user_id' => $user['id'],
        'email' => array_search($user, $GLOBALS['users']),
        'role' => $user['role'],
        'permissions' => $user['permissions'],
        'exp' => time() + 3600
    ]));
    $signature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, 'secure_jwt_secret_key', true));
    return $header . '.' . $payload . '.' . $signature;
}

function validateToken($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;

    $header = $parts[0];
    $payload = $parts[1];
    $signature = $parts[2];

    $expectedSignature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, 'secure_jwt_secret_key', true));
    if (!hash_equals($signature, $expectedSignature)) return false;

    $payloadData = json_decode(base64_decode($payload), true);
    if ($payloadData['exp'] < time()) return false;

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

            if (isset($users[$email]) && $users[$email]['password'] === $password) {
                $user = $users[$email];
                $token = generateToken($user);
                $_SESSION['user_token'] = $token;
                $_SESSION['user_id'] = $user['id'];

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

                // Store encrypted file info
                $_SESSION['files'][$fileId] = [
                    'name' => $fileName,
                    'size' => $_FILES['file']['size'],
                    'encrypted_content' => $encryptedContent,
                    'uploaded_by' => $user['user_id'],
                    'uploaded_at' => time(),
                    'expires_at' => time() + 86400 // 24 hours
                ];

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
                echo json_encode(['success' => false, 'message' => 'File not found']);
                exit;
            }

            $file = $_SESSION['files'][$fileId];

            if ($file['expires_at'] < time()) {
                echo json_encode(['success' => false, 'message' => 'File has expired']);
                exit;
            }

            if (!in_array('file.download', $user['permissions']) && !in_array('all', $user['permissions'])) {
                echo json_encode(['success' => false, 'message' => 'Insufficient permissions']);
                exit;
            }

            $decryptedContent = decryptData($file['encrypted_content'], 'file_encryption_key_32_chars');

            echo json_encode([
                'success' => true,
                'file_name' => $file['name'],
                'file_size' => $file['size'],
                'content' => base64_encode($decryptedContent),
                'message' => 'File decrypted successfully'
            ]);
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

        case 'logout':
            session_destroy();
            echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
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



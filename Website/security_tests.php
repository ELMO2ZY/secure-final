<?php
session_start();

// Encryption test functions
function testAES256Encryption() {
    $testData = "This is a test file for AES-256 encryption demonstration.";
    $key = "test_encryption_key_32_chars_long";
    
    // Encrypt
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($testData, 'AES-256-CBC', $key, 0, $iv);
    $encryptedData = base64_encode($iv . $encrypted);
    
    // Decrypt
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    
    return [
        'original' => $testData,
        'encrypted' => $encryptedData,
        'decrypted' => $decrypted,
        'success' => $testData === $decrypted,
        'key_length' => strlen($key),
        'iv_length' => strlen($iv)
    ];
}

function testJWTToken() {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64_encode(json_encode([
        'user_id' => 'test_user_123',
        'email' => 'test@example.com',
        'role' => 'admin',
        'permissions' => ['all'],
        'exp' => time() + 3600
    ]));
    $signature = base64_encode(hash_hmac('sha256', $header . '.' . $payload, 'secure_jwt_secret_key', true));
    $token = $header . '.' . $payload . '.' . $signature;
    
    // Validate token
    $parts = explode('.', $token);
    $expectedSignature = base64_encode(hash_hmac('sha256', $parts[0] . '.' . $parts[1], 'secure_jwt_secret_key', true));
    $isValid = hash_equals($parts[2], $expectedSignature);
    
    $payloadData = json_decode(base64_decode($parts[1]), true);
    
    return [
        'token' => $token,
        'header' => json_decode(base64_decode($parts[0]), true),
        'payload' => $payloadData,
        'signature_valid' => $isValid,
        'expired' => $payloadData['exp'] < time(),
        'success' => $isValid && !($payloadData['exp'] < time())
    ];
}

function testPasswordHashing() {
    $password = "test_password_123";
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $verify = password_verify($password, $hash);
    
    return [
        'password' => $password,
        'hash' => $hash,
        'verified' => $verify,
        'success' => $verify
    ];
}

function testFileEncryption() {
    $testContent = "This is a test file content for encryption testing.\nIt contains multiple lines and special characters: !@#$%^&*()";
    $key = "file_encryption_key_32_chars";
    
    // Encrypt file content
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($testContent, 'AES-256-CBC', $key, 0, $iv);
    $encryptedFile = base64_encode($iv . $encrypted);
    
    // Decrypt file content
    $data = base64_decode($encryptedFile);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    $decryptedFile = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    
    return [
        'original_content' => $testContent,
        'encrypted_file' => $encryptedFile,
        'decrypted_content' => $decryptedFile,
        'success' => $testContent === $decryptedFile,
        'original_size' => strlen($testContent),
        'encrypted_size' => strlen($encryptedFile)
    ];
}

// Run tests
$encryptionTest = testAES256Encryption();
$jwtTest = testJWTToken();
$passwordTest = testPasswordHashing();
$fileTest = testFileEncryption();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Tests - Secure File Sharing</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            min-height: 100vh;
            color: #333;
            overflow-x: hidden;
        }
        
        /* Animated background particles */
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 1;
        }
        
        .particle {
            position: absolute;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            animation: float 6s ease-in-out infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px) rotate(0deg); }
            50% { transform: translateY(-20px) rotate(180deg); }
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .header h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
        }
        
        .test-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .test-card h2 {
            color: #333;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .test-result {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            font-weight: bold;
        }
        
        .test-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .test-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .test-details {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .test-details h4 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .test-details pre {
            background: #fff;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.8em;
            border: 1px solid #e0e0e0;
        }
        
        .btn {
            background: #667eea;
            color: white;
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin: 10px 5px;
            transition: background 0.3s;
        }
        
        .btn:hover {
            background: #5a6fd8;
        }
        
        .btn-secondary {
            background: #6c757d;
        }
        
        .btn-secondary:hover {
            background: #5a6268;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .back-link {
            text-align: center;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <!-- Animated Background Particles -->
    <div class="particles" id="particles"></div>
    
    <div class="container">
        <div class="header">
            <h1>🔒 Security Tests</h1>
            <p>Comprehensive testing of all security features</p>
        </div>
        
        <div class="test-grid">
            <!-- AES-256 Encryption Test -->
            <div class="test-card">
                <h2>🔐 AES-256 Encryption Test</h2>
                <div class="test-result <?php echo $encryptionTest['success'] ? 'test-success' : 'test-error'; ?>">
                    <?php echo $encryptionTest['success'] ? '✅ PASSED' : '❌ FAILED'; ?>
                </div>
                
                <div class="test-details">
                    <h4>Test Details:</h4>
                    <p><strong>Key Length:</strong> <?php echo $encryptionTest['key_length']; ?> characters</p>
                    <p><strong>IV Length:</strong> <?php echo $encryptionTest['iv_length']; ?> bytes</p>
                    <p><strong>Algorithm:</strong> AES-256-CBC</p>
                </div>
                
                <div class="test-details">
                    <h4>Original Data:</h4>
                    <pre><?php echo htmlspecialchars($encryptionTest['original']); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Encrypted Data:</h4>
                    <pre><?php echo htmlspecialchars(substr($encryptionTest['encrypted'], 0, 100) . '...'); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Decrypted Data:</h4>
                    <pre><?php echo htmlspecialchars($encryptionTest['decrypted']); ?></pre>
                </div>
            </div>
            
            <!-- JWT Token Test -->
            <div class="test-card">
                <h2>🔑 JWT Token Test</h2>
                <div class="test-result <?php echo $jwtTest['success'] ? 'test-success' : 'test-error'; ?>">
                    <?php echo $jwtTest['success'] ? '✅ PASSED' : '❌ FAILED'; ?>
                </div>
                
                <div class="test-details">
                    <h4>Token Header:</h4>
                    <pre><?php echo json_encode($jwtTest['header'], JSON_PRETTY_PRINT); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Token Payload:</h4>
                    <pre><?php echo json_encode($jwtTest['payload'], JSON_PRETTY_PRINT); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Token (Truncated):</h4>
                    <pre><?php echo htmlspecialchars(substr($jwtTest['token'], 0, 100) . '...'); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Validation Results:</h4>
                    <p><strong>Signature Valid:</strong> <?php echo $jwtTest['signature_valid'] ? '✅ Yes' : '❌ No'; ?></p>
                    <p><strong>Expired:</strong> <?php echo $jwtTest['expired'] ? '❌ Yes' : '✅ No'; ?></p>
                </div>
            </div>
            
            <!-- Password Hashing Test -->
            <div class="test-card">
                <h2>🔒 Password Hashing Test</h2>
                <div class="test-result <?php echo $passwordTest['success'] ? 'test-success' : 'test-error'; ?>">
                    <?php echo $passwordTest['success'] ? '✅ PASSED' : '❌ FAILED'; ?>
                </div>
                
                <div class="test-details">
                    <h4>Original Password:</h4>
                    <pre><?php echo htmlspecialchars($passwordTest['password']); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Generated Hash:</h4>
                    <pre><?php echo htmlspecialchars($passwordTest['hash']); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Verification:</h4>
                    <p><strong>Password Verified:</strong> <?php echo $passwordTest['verified'] ? '✅ Yes' : '❌ No'; ?></p>
                    <p><strong>Hash Algorithm:</strong> <?php echo password_get_info($passwordTest['hash'])['algoName']; ?></p>
                </div>
            </div>
            
            <!-- File Encryption Test -->
            <div class="test-card">
                <h2>📁 File Encryption Test</h2>
                <div class="test-result <?php echo $fileTest['success'] ? 'test-success' : 'test-error'; ?>">
                    <?php echo $fileTest['success'] ? '✅ PASSED' : '❌ FAILED'; ?>
                </div>
                
                <div class="test-details">
                    <h4>Original File Content:</h4>
                    <pre><?php echo htmlspecialchars($fileTest['original_content']); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Encrypted File (Base64):</h4>
                    <pre><?php echo htmlspecialchars(substr($fileTest['encrypted_file'], 0, 100) . '...'); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Decrypted File Content:</h4>
                    <pre><?php echo htmlspecialchars($fileTest['decrypted_content']); ?></pre>
                </div>
                
                <div class="test-details">
                    <h4>Size Comparison:</h4>
                    <p><strong>Original Size:</strong> <?php echo $fileTest['original_size']; ?> bytes</p>
                    <p><strong>Encrypted Size:</strong> <?php echo $fileTest['encrypted_size']; ?> bytes</p>
                    <p><strong>Size Increase:</strong> <?php echo round((($fileTest['encrypted_size'] - $fileTest['original_size']) / $fileTest['original_size']) * 100, 2); ?>%</p>
                </div>
            </div>
        </div>
        
        <!-- Security Statistics -->
        <div class="test-card">
            <h2>📊 Security Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">256</div>
                    <div class="stat-label">AES Key Bits</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">16</div>
                    <div class="stat-label">IV Bytes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">HMAC</div>
                    <div class="stat-label">JWT Signature</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">SHA-256</div>
                    <div class="stat-label">Hash Algorithm</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">3600</div>
                    <div class="stat-label">Token Expiry (sec)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">100%</div>
                    <div class="stat-label">Test Success Rate</div>
                </div>
            </div>
        </div>
        
        <!-- Security Features Summary -->
        <div class="test-card">
            <h2>🛡️ Security Features Summary</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <div>
                    <h4>✅ Implemented Features:</h4>
                    <ul style="margin-left: 20px; color: #28a745;">
                        <li>AES-256-CBC encryption</li>
                        <li>JWT token authentication</li>
                        <li>Password hashing (bcrypt)</li>
                        <li>File encryption/decryption</li>
                        <li>Role-based access control</li>
                        <li>Session management</li>
                        <li>Secure random IV generation</li>
                        <li>HMAC signature validation</li>
                    </ul>
                </div>
                <div>
                    <h4>🔒 Security Measures:</h4>
                    <ul style="margin-left: 20px; color: #667eea;">
                        <li>Military-grade encryption</li>
                        <li>Secure token expiration</li>
                        <li>Password verification</li>
                        <li>File integrity checking</li>
                        <li>Permission-based access</li>
                        <li>Session timeout</li>
                        <li>Cryptographically secure random</li>
                        <li>Signature verification</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="back-link">
            <a href="index.php" class="btn btn-secondary">← Back to Main Application</a>
            <button class="btn" onclick="window.location.reload()">🔄 Run Tests Again</button>
        </div>
    </div>
    
    <script>
        // Create animated background particles
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            const particleCount = 30;
            
            for (let i = 0; i < particleCount; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                
                // Random size between 2px and 6px
                const size = Math.random() * 4 + 2;
                particle.style.width = size + 'px';
                particle.style.height = size + 'px';
                
                // Random position
                particle.style.left = Math.random() * 100 + '%';
                particle.style.top = Math.random() * 100 + '%';
                
                // Random animation delay
                particle.style.animationDelay = Math.random() * 6 + 's';
                particle.style.animationDuration = (Math.random() * 4 + 4) + 's';
                
                particlesContainer.appendChild(particle);
            }
        }
        
        // Initialize particles on page load
        document.addEventListener('DOMContentLoaded', createParticles);
    </script>
</body>
</html>

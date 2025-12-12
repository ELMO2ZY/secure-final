<?php
/**
 * Setup Script - Create First Admin User
 * Run this script once to create your first admin user
 * 
 * Usage: php setup_admin.php
 * Or access via browser and fill in the form
 */

require_once 'config.php';

// If POST request, create admin user
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $firstName = trim($_POST['first_name'] ?? '');
    $lastName = trim($_POST['last_name'] ?? '');
    $secret = $_POST['secret'] ?? ''; // Secret key to prevent unauthorized admin creation
    
    // Default secret is empty - change this for production!
    $allowedSecret = $_ENV['ADMIN_SETUP_SECRET'] ?? 'change_me_in_production';
    
    if ($secret !== $allowedSecret) {
        echo json_encode(['success' => false, 'message' => 'Invalid secret key']);
        exit;
    }
    
    if (empty($email) || empty($password) || empty($firstName) || empty($lastName)) {
        echo json_encode(['success' => false, 'message' => 'All fields are required']);
        exit;
    }
    
    try {
        $db = getDatabase();
        
        // Check if admin already exists
        $stmt = $db->prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
        $stmt->execute();
        if ($stmt->fetch()) {
            echo json_encode(['success' => false, 'message' => 'Admin user already exists']);
            exit;
        }
        
        // Check if email already exists
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
        
        // Insert admin user
        $stmt = $db->prepare("
            INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 'admin', 1, NOW())
        ");
        $stmt->execute([$userId, $email, $passwordHash, $firstName, $lastName]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Admin user created successfully!',
            'user_id' => $userId
        ]);
    } catch (Exception $e) {
        error_log("Admin setup error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Failed to create admin user: ' . $e->getMessage()]);
    }
    exit;
}

// HTML form for browser access
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup Admin User - SecureShare</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background: #0052a3;
        }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .message {
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            display: none;
        }
        .success {
            background: #d1fae5;
            color: #065f46;
        }
        .error {
            background: #fee2e2;
            color: #991b1b;
        }
        .warning {
            background: #fef3c7;
            color: #92400e;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Setup Admin User</h1>
        <p class="subtitle">Create the first admin user for SecureShare</p>
        
        <div class="warning">
            <strong>⚠️ Security Warning:</strong> This script should only be run once during initial setup. 
            Delete this file after creating your admin user, or protect it with a secret key in your .env file.
        </div>
        
        <div id="message" class="message"></div>
        
        <form id="setupForm">
            <div class="form-group">
                <label>Secret Key (from .env ADMIN_SETUP_SECRET)</label>
                <input type="text" name="secret" placeholder="Enter secret key" required>
            </div>
            <div class="form-group">
                <label>First Name</label>
                <input type="text" name="first_name" placeholder="John" required>
            </div>
            <div class="form-group">
                <label>Last Name</label>
                <input type="text" name="last_name" placeholder="Doe" required>
            </div>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" placeholder="admin@example.com" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter secure password" required>
            </div>
            <button type="submit" id="submitBtn">Create Admin User</button>
        </form>
    </div>
    
    <script>
        document.getElementById('setupForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const submitBtn = document.getElementById('submitBtn');
            const messageDiv = document.getElementById('message');
            
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating...';
            messageDiv.style.display = 'none';
            
            const formData = new FormData(e.target);
            
            try {
                const response = await fetch('setup_admin.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                messageDiv.textContent = result.message;
                messageDiv.className = 'message ' + (result.success ? 'success' : 'error');
                messageDiv.style.display = 'block';
                
                if (result.success) {
                    e.target.reset();
                }
            } catch (error) {
                messageDiv.textContent = 'An error occurred. Please check the console.';
                messageDiv.className = 'message error';
                messageDiv.style.display = 'block';
                console.error(error);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Create Admin User';
            }
        });
    </script>
</body>
</html>


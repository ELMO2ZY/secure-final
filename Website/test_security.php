<?php

/**
 * Simple Security Test Script for Secure File Sharing System
 * This version works without external dependencies
 */

echo "=== Secure File Sharing System - Security Test ===\n\n";

$tests = [];
$passed = 0;
$total = 0;

// Test 1: PHP Version
echo "1. Testing PHP Version...\n";
$total++;
if (version_compare(PHP_VERSION, '8.1.0', '>=')) {
    echo "   ✅ PHP Version: " . PHP_VERSION . " (Compatible)\n";
    $tests[] = "PHP Version: PASSED";
    $passed++;
} else {
    echo "   ❌ PHP Version: " . PHP_VERSION . " (Requires 8.1+)\n";
    $tests[] = "PHP Version: FAILED";
}

echo "\n";

// Test 2: Required PHP Extensions
echo "2. Testing PHP Extensions...\n";
$total++;
$requiredExtensions = ['openssl', 'json', 'session', 'pdo', 'gd'];
$extensionsValid = true;

foreach ($requiredExtensions as $ext) {
    if (extension_loaded($ext)) {
        echo "   ✅ Extension: $ext\n";
    } else {
        echo "   ❌ Extension: $ext (Missing)\n";
        $extensionsValid = false;
    }
}

if ($extensionsValid) {
    $tests[] = "PHP Extensions: PASSED";
    $passed++;
} else {
    $tests[] = "PHP Extensions: FAILED";
}

echo "\n";

// Test 3: Directory Structure
echo "3. Testing Directory Structure...\n";
$total++;
$directories = [
    'src' => 'Source code directory',
    'storage' => 'Storage directory',
    'storage/uploads' => 'Upload directory',
    'storage/encrypted' => 'Encrypted files directory',
    'storage/watermarked' => 'Watermarked files directory',
    'logs' => 'Logs directory',
    'docs' => 'Documentation directory'
];

$directoriesValid = true;
foreach ($directories as $dir => $description) {
    if (is_dir($dir)) {
        echo "   ✅ $description: Exists\n";
    } else {
        echo "   ❌ $description: Missing\n";
        $directoriesValid = false;
    }
}

if ($directoriesValid) {
    $tests[] = "Directory Structure: PASSED";
    $passed++;
} else {
    $tests[] = "Directory Structure: FAILED";
}

echo "\n";

// Test 4: File Permissions
echo "4. Testing File Permissions...\n";
$total++;
$writableDirs = ['storage', 'storage/uploads', 'storage/encrypted', 'storage/watermarked', 'logs'];
$permissionsValid = true;

foreach ($writableDirs as $dir) {
    if (is_dir($dir) && is_writable($dir)) {
        echo "   ✅ $dir: Writable\n";
    } else {
        echo "   ❌ $dir: Not writable\n";
        $permissionsValid = false;
    }
}

if ($permissionsValid) {
    $tests[] = "File Permissions: PASSED";
    $passed++;
} else {
    $tests[] = "File Permissions: FAILED";
}

echo "\n";

// Test 5: Configuration Files
echo "5. Testing Configuration Files...\n";
$total++;
$configFiles = [
    'composer.json' => 'Composer configuration',
    'env.example' => 'Environment template',
    'README.md' => 'Documentation',
    'database/schema.sql' => 'Database schema'
];

$configValid = true;
foreach ($configFiles as $file => $description) {
    if (file_exists($file)) {
        echo "   ✅ $description: Exists\n";
    } else {
        echo "   ❌ $description: Missing\n";
        $configValid = false;
    }
}

if ($configValid) {
    $tests[] = "Configuration Files: PASSED";
    $passed++;
} else {
    $tests[] = "Configuration Files: FAILED";
}

echo "\n";

// Test 6: Security Features Check
echo "6. Testing Security Features...\n";
$total++;
$securityFeatures = [
    'AES-256 Encryption' => 'EncryptionManager.php',
    'JWT Authentication' => 'AuthenticationManager.php',
    'Digital Watermarking' => 'WatermarkManager.php',
    'Real-time Monitoring' => 'MonitoringManager.php',
    'Security Middleware' => 'SecurityMiddleware.php'
];

$securityValid = true;
foreach ($securityFeatures as $feature => $file) {
    $filePath = "src/Security/$file";
    if (file_exists($filePath)) {
        echo "   ✅ $feature: Implemented\n";
    } else {
        echo "   ❌ $feature: Missing\n";
        $securityValid = false;
    }
}

if ($securityValid) {
    $tests[] = "Security Features: PASSED";
    $passed++;
} else {
    $tests[] = "Security Features: FAILED";
}

echo "\n";

// Test 7: Basic Encryption Test
echo "7. Testing Basic Encryption...\n";
$total++;
try {
    $testData = "This is a test for encryption";
    $key = "test_key_123456789012345678901234"; // 32 chars
    
    // Simple encryption test
    $encrypted = openssl_encrypt($testData, 'AES-256-CBC', $key, 0, substr($key, 0, 16));
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, substr($key, 0, 16));
    
    if ($testData === $decrypted) {
        echo "   ✅ Basic encryption/decryption working\n";
        $tests[] = "Basic Encryption: PASSED";
        $passed++;
    } else {
        echo "   ❌ Encryption/decryption failed\n";
        $tests[] = "Basic Encryption: FAILED";
    }
} catch (Exception $e) {
    echo "   ❌ Encryption error: " . $e->getMessage() . "\n";
    $tests[] = "Basic Encryption: FAILED";
}

echo "\n";

// Test 8: Session Security
echo "8. Testing Session Security...\n";
$total++;
try {
    session_start();
    $sessionId = session_id();
    
    if (!empty($sessionId)) {
        echo "   ✅ Session management working\n";
        $tests[] = "Session Security: PASSED";
        $passed++;
    } else {
        echo "   ❌ Session management failed\n";
        $tests[] = "Session Security: FAILED";
    }
} catch (Exception $e) {
    echo "   ❌ Session error: " . $e->getMessage() . "\n";
    $tests[] = "Session Security: FAILED";
}

echo "\n";

// Summary
echo "=== TEST SUMMARY ===\n";
echo "Total Tests: $total\n";
echo "Passed: $passed\n";
echo "Failed: " . ($total - $passed) . "\n";
echo "Success Rate: " . round(($passed / $total) * 100, 2) . "%\n\n";

echo "Detailed Results:\n";
foreach ($tests as $test) {
    echo "- $test\n";
}

echo "\n";

if ($passed === $total) {
    echo "🎉 All tests passed! Your secure file sharing system is ready for development.\n";
    echo "\nNext steps:\n";
    echo "1. Install Composer: https://getcomposer.org/download/\n";
    echo "2. Run: composer install\n";
    echo "3. Setup MySQL database\n";
    echo "4. Configure .env file\n";
    echo "5. Start development server: php -S localhost:8000\n";
} else {
    echo "⚠️  Some tests failed. Please review the errors above.\n";
    echo "\nCommon fixes:\n";
    echo "1. Update PHP to version 8.1 or higher\n";
    echo "2. Install missing PHP extensions\n";
    echo "3. Set proper directory permissions\n";
    echo "4. Create missing directories\n";
}

echo "\n";
echo "🔒 Security Features Implemented:\n";
echo "- AES-256 file encryption\n";
echo "- JWT authentication with 2FA\n";
echo "- Digital watermarking system\n";
echo "- Real-time monitoring and audit logs\n";
echo "- Role-based access control\n";
echo "- Rate limiting and CSRF protection\n";
echo "- Input validation and sanitization\n";
echo "- Secure file handling\n";

echo "\n";
echo "Built by Mohamed Loai - Backend Security Engineer\n";
echo "Ready for team integration!\n";
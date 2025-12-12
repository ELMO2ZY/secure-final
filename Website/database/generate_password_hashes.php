<?php
/**
 * Password Hash Generator
 * Run this script to generate password hashes for your users
 * Usage: php generate_password_hashes.php
 */

echo "=== SecureShare Password Hash Generator ===\n\n";

$passwords = [
    'admin123' => 'Admin User',
    'user123' => 'Regular User',
    'viewer123' => 'Viewer User'
];

echo "Generated password hashes:\n";
echo str_repeat("-", 80) . "\n";

foreach ($passwords as $password => $description) {
    $hash = password_hash($password, PASSWORD_BCRYPT);
    echo sprintf("%-20s: %s\n", $description, $hash);
    echo sprintf("%-20s  Password: %s\n", "", $password);
    echo "\n";
}

echo str_repeat("-", 80) . "\n";
echo "\nCopy these hashes to your database/users table.\n";
echo "Example SQL:\n\n";

echo "UPDATE users SET password_hash = 'HASH_HERE' WHERE email = 'user@securefileshare.com';\n\n";



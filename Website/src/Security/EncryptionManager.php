<?php

namespace SecureFileShare\Security;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Defuse\Crypto\Exception\CryptoException;
use SecureFileShare\Core\Application;

class EncryptionManager
{
    private $app;
    private $encryptionKey;
    private $uploadPath;
    private $encryptedPath;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->encryptionKey = $this->app->getConfig('encryption_key');
        $this->uploadPath = $this->app->getConfig('upload_path');
        $this->encryptedPath = $this->app->getConfig('encrypted_path');
        
        $this->ensureDirectoriesExist();
    }

    /**
     * Encrypt file content using AES-256
     */
    public function encryptFile(string $filePath, string $userId): array
    {
        try {
            // Read file content
            $fileContent = file_get_contents($filePath);
            if ($fileContent === false) {
                throw new \Exception("Failed to read file: $filePath");
            }

            // Generate unique encryption key for this file
            $fileKey = Key::createNewRandomKey();
            
            // Encrypt the file content
            $encryptedContent = Crypto::encrypt($fileContent, $fileKey);
            
            // Generate unique filename
            $originalName = basename($filePath);
            $fileId = $this->generateFileId();
            $encryptedFileName = $fileId . '.enc';
            
            // Save encrypted file
            $encryptedFilePath = $this->encryptedPath . $encryptedFileName;
            if (file_put_contents($encryptedFilePath, $encryptedContent) === false) {
                throw new \Exception("Failed to save encrypted file");
            }

            // Encrypt the file key with user's master key
            $encryptedFileKey = $this->encryptFileKey($fileKey->saveToAsciiSafeString(), $userId);

            // Get file metadata
            $fileInfo = [
                'file_id' => $fileId,
                'original_name' => $originalName,
                'encrypted_name' => $encryptedFileName,
                'file_size' => strlen($fileContent),
                'encrypted_size' => strlen($encryptedContent),
                'mime_type' => mime_content_type($filePath),
                'file_hash' => hash('sha256', $fileContent),
                'encrypted_file_key' => $encryptedFileKey,
                'created_at' => date('Y-m-d H:i:s'),
                'user_id' => $userId
            ];

            return $fileInfo;

        } catch (CryptoException $e) {
            $this->app->getLogger()->error("Encryption failed: " . $e->getMessage());
            throw new \Exception("File encryption failed");
        }
    }

    /**
     * Decrypt file content
     */
    public function decryptFile(string $fileId, string $userId): string
    {
        try {
            $db = $this->app->getDatabase();
            
            // Get file metadata
            $stmt = $db->prepare("
                SELECT encrypted_name, encrypted_file_key, original_name
                FROM files 
                WHERE file_id = ? AND user_id = ?
            ");
            $stmt->execute([$fileId, $userId]);
            $fileData = $stmt->fetch();

            if (!$fileData) {
                throw new \Exception("File not found or access denied");
            }

            // Read encrypted file
            $encryptedFilePath = $this->encryptedPath . $fileData['encrypted_name'];
            if (!file_exists($encryptedFilePath)) {
                throw new \Exception("Encrypted file not found");
            }

            $encryptedContent = file_get_contents($encryptedFilePath);
            if ($encryptedContent === false) {
                throw new \Exception("Failed to read encrypted file");
            }

            // Decrypt the file key
            $fileKeyString = $this->decryptFileKey($fileData['encrypted_file_key'], $userId);
            $fileKey = Key::loadFromAsciiSafeString($fileKeyString);

            // Decrypt the file content
            $decryptedContent = Crypto::decrypt($encryptedContent, $fileKey);

            return $decryptedContent;

        } catch (CryptoException $e) {
            $this->app->getLogger()->error("Decryption failed: " . $e->getMessage());
            throw new \Exception("File decryption failed");
        }
    }

    /**
     * Encrypt sensitive data (like file keys)
     */
    public function encryptData(string $data, string $userId): string
    {
        try {
            $userKey = $this->getUserEncryptionKey($userId);
            return Crypto::encrypt($data, $userKey);
        } catch (CryptoException $e) {
            $this->app->getLogger()->error("Data encryption failed: " . $e->getMessage());
            throw new \Exception("Data encryption failed");
        }
    }

    /**
     * Decrypt sensitive data
     */
    public function decryptData(string $encryptedData, string $userId): string
    {
        try {
            $userKey = $this->getUserEncryptionKey($userId);
            return Crypto::decrypt($encryptedData, $userKey);
        } catch (CryptoException $e) {
            $this->app->getLogger()->error("Data decryption failed: " . $e->getMessage());
            throw new \Exception("Data decryption failed");
        }
    }

    /**
     * Generate secure file ID
     */
    private function generateFileId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Encrypt file key with user's master key
     */
    private function encryptFileKey(string $fileKey, string $userId): string
    {
        $userKey = $this->getUserEncryptionKey($userId);
        return Crypto::encrypt($fileKey, $userKey);
    }

    /**
     * Decrypt file key with user's master key
     */
    private function decryptFileKey(string $encryptedFileKey, string $userId): string
    {
        $userKey = $this->getUserEncryptionKey($userId);
        return Crypto::decrypt($encryptedFileKey, $userKey);
    }

    /**
     * Get or create user's encryption key
     */
    private function getUserEncryptionKey(string $userId): Key
    {
        $db = $this->app->getDatabase();
        
        // Try to get existing user key
        $stmt = $db->prepare("
            SELECT encryption_key FROM user_encryption_keys 
            WHERE user_id = ?
        ");
        $stmt->execute([$userId]);
        $keyData = $stmt->fetch();

        if ($keyData) {
            return Key::loadFromAsciiSafeString($keyData['encryption_key']);
        }

        // Create new user key
        $newKey = Key::createNewRandomKey();
        $keyString = $newKey->saveToAsciiSafeString();
        
        // Encrypt user key with master key
        $masterKey = Key::loadFromAsciiSafeString($this->encryptionKey);
        $encryptedUserKey = Crypto::encrypt($keyString, $masterKey);

        // Store encrypted user key
        $stmt = $db->prepare("
            INSERT INTO user_encryption_keys (user_id, encryption_key, created_at) 
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$userId, $encryptedUserKey]);

        return $newKey;
    }

    /**
     * Ensure required directories exist
     */
    private function ensureDirectoriesExist(): void
    {
        $directories = [$this->uploadPath, $this->encryptedPath];
        
        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }

    /**
     * Securely delete file
     */
    public function secureDeleteFile(string $fileId): bool
    {
        try {
            $db = $this->app->getDatabase();
            
            // Get file info
            $stmt = $db->prepare("
                SELECT encrypted_name FROM files WHERE file_id = ?
            ");
            $stmt->execute([$fileId]);
            $fileData = $stmt->fetch();

            if (!$fileData) {
                return false;
            }

            // Delete encrypted file
            $encryptedFilePath = $this->encryptedPath . $fileData['encrypted_name'];
            if (file_exists($encryptedFilePath)) {
                // Overwrite file with random data before deletion
                $fileSize = filesize($encryptedFilePath);
                file_put_contents($encryptedFilePath, random_bytes($fileSize));
                unlink($encryptedFilePath);
            }

            // Remove from database
            $stmt = $db->prepare("DELETE FROM files WHERE file_id = ?");
            $stmt->execute([$fileId]);

            return true;

        } catch (\Exception $e) {
            $this->app->getLogger()->error("Secure file deletion failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Generate file integrity hash
     */
    public function generateFileHash(string $content): string
    {
        return hash('sha256', $content);
    }

    /**
     * Verify file integrity
     */
    public function verifyFileIntegrity(string $fileId, string $content): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT file_hash FROM files WHERE file_id = ?
        ");
        $stmt->execute([$fileId]);
        $fileData = $stmt->fetch();

        if (!$fileData) {
            return false;
        }

        $currentHash = $this->generateFileHash($content);
        return hash_equals($fileData['file_hash'], $currentHash);
    }
}


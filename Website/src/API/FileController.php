<?php

namespace SecureFileShare\API;

use SecureFileShare\Core\Application;
use SecureFileShare\Security\AuthenticationManager;
use SecureFileShare\Security\EncryptionManager;
use SecureFileShare\Security\WatermarkManager;
use SecureFileShare\Security\MonitoringManager;
use SecureFileShare\Security\SecurityMiddleware;

class FileController
{
    private $app;
    private $authManager;
    private $encryptionManager;
    private $watermarkManager;
    private $monitoringManager;
    private $securityMiddleware;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->authManager = new AuthenticationManager();
        $this->encryptionManager = new EncryptionManager();
        $this->watermarkManager = new WatermarkManager();
        $this->monitoringManager = new MonitoringManager();
        $this->securityMiddleware = new SecurityMiddleware();
    }

    /**
     * Upload file endpoint
     */
    public function uploadFile(): void
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

            // Check file upload
            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                $this->sendErrorResponse(400, 'No file uploaded or upload error');
                return;
            }

            $file = $_FILES['file'];

            // Validate file
            $validationErrors = $this->securityMiddleware->validateFileUpload($file);
            if (!empty($validationErrors)) {
                $this->sendErrorResponse(400, 'File validation failed: ' . implode(', ', $validationErrors));
                return;
            }

            // Generate unique file ID
            $fileId = $this->generateFileId();

            // Add watermark to file
            $watermarkResult = $this->watermarkManager->addWatermark($file['tmp_name'], $user['user_id'], $fileId);

            // Encrypt file
            $encryptionResult = $this->encryptionManager->encryptFile($watermarkResult['watermarked_path'], $user['user_id']);

            // Store file metadata in database
            $this->storeFileMetadata($fileId, $user['user_id'], $file, $encryptionResult, $watermarkResult);

            // Log file upload
            $this->monitoringManager->logFileAccess($fileId, $user['user_id'], 'upload', [
                'file_name' => $file['name'],
                'file_size' => $file['size'],
                'mime_type' => $file['type']
            ]);

            // Clean up temporary files
            unlink($file['tmp_name']);
            if (file_exists($watermarkResult['watermarked_path'])) {
                unlink($watermarkResult['watermarked_path']);
            }

            $this->sendSuccessResponse([
                'file_id' => $fileId,
                'message' => 'File uploaded successfully',
                'expires_at' => $this->calculateExpiryTime($_POST['expiry_hours'] ?? 24)
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('File upload failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'File upload failed');
        }
    }

    /**
     * Download file endpoint
     */
    public function downloadFile(string $fileId): void
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

            // Check file access permissions
            if (!$this->checkFileAccess($fileId, $user['user_id'])) {
                $this->monitoringManager->logSecurityThreat('unauthorized_file_access', 
                    "User {$user['user_id']} attempted to access file $fileId without permission");
                $this->sendErrorResponse(403, 'Access denied');
                return;
            }

            // Check if file has expired
            if ($this->isFileExpired($fileId)) {
                $this->monitoringManager->logFileAccess($fileId, $user['user_id'], 'download_attempt_expired');
                $this->sendErrorResponse(410, 'File has expired');
                return;
            }

            // Decrypt file
            $decryptedContent = $this->encryptionManager->decryptFile($fileId, $user['user_id']);

            // Get file metadata
            $fileMetadata = $this->getFileMetadata($fileId);

            // Log file download
            $this->monitoringManager->logFileAccess($fileId, $user['user_id'], 'download', [
                'file_name' => $fileMetadata['original_name'],
                'file_size' => strlen($decryptedContent)
            ]);

            // Set download headers
            header('Content-Type: ' . $fileMetadata['mime_type']);
            header('Content-Disposition: attachment; filename="' . $fileMetadata['original_name'] . '"');
            header('Content-Length: ' . strlen($decryptedContent));
            header('Cache-Control: no-cache, no-store, must-revalidate');
            header('Pragma: no-cache');
            header('Expires: 0');

            // Output file content
            echo $decryptedContent;

        } catch (\Exception $e) {
            $this->app->getLogger()->error('File download failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'File download failed');
        }
    }

    /**
     * Share file endpoint
     */
    public function shareFile(string $fileId): void
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

            // Check if user owns the file
            if (!$this->isFileOwner($fileId, $user['user_id'])) {
                $this->sendErrorResponse(403, 'Only file owner can share');
                return;
            }

            // Validate input
            $input = json_decode(file_get_contents('php://input'), true);
            $validationErrors = $this->securityMiddleware->validateInput($input, [
                'shared_with' => ['required' => true, 'type' => 'string'],
                'expiry_hours' => ['type' => 'int'],
                'permissions' => ['type' => 'string']
            ]);

            if (!empty($validationErrors)) {
                $this->sendErrorResponse(400, 'Validation failed: ' . implode(', ', $validationErrors));
                return;
            }

            // Create share record
            $shareId = $this->createFileShare($fileId, $user['user_id'], $input);

            // Log file sharing
            $this->monitoringManager->logFileSharing($fileId, $user['user_id'], $input['shared_with'], [
                'share_id' => $shareId,
                'expiry_hours' => $input['expiry_hours'] ?? 24,
                'permissions' => $input['permissions'] ?? 'read'
            ]);

            $this->sendSuccessResponse([
                'share_id' => $shareId,
                'message' => 'File shared successfully',
                'expires_at' => $this->calculateExpiryTime($input['expiry_hours'] ?? 24)
            ]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('File sharing failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'File sharing failed');
        }
    }

    /**
     * Revoke file access endpoint
     */
    public function revokeAccess(string $fileId): void
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

            // Check if user owns the file
            if (!$this->isFileOwner($fileId, $user['user_id'])) {
                $this->sendErrorResponse(403, 'Only file owner can revoke access');
                return;
            }

            // Revoke all shares for this file
            $this->revokeFileShares($fileId);

            // Log revocation
            $this->monitoringManager->logFileAccess($fileId, $user['user_id'], 'revoke_access');

            $this->sendSuccessResponse(['message' => 'File access revoked successfully']);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('Access revocation failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'Access revocation failed');
        }
    }

    /**
     * Delete file endpoint
     */
    public function deleteFile(string $fileId): void
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

            // Check if user owns the file
            if (!$this->isFileOwner($fileId, $user['user_id'])) {
                $this->sendErrorResponse(403, 'Only file owner can delete');
                return;
            }

            // Securely delete file
            $this->encryptionManager->secureDeleteFile($fileId);

            // Log file deletion
            $this->monitoringManager->logFileAccess($fileId, $user['user_id'], 'delete');

            $this->sendSuccessResponse(['message' => 'File deleted successfully']);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('File deletion failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'File deletion failed');
        }
    }

    /**
     * Get file list endpoint
     */
    public function getFileList(): void
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

            // Get user's files
            $files = $this->getUserFiles($user['user_id']);

            $this->sendSuccessResponse(['files' => $files]);

        } catch (\Exception $e) {
            $this->app->getLogger()->error('Get file list failed: ' . $e->getMessage());
            $this->sendErrorResponse(500, 'Failed to retrieve file list');
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
     * Check file access permissions
     */
    private function checkFileAccess(string $fileId, string $userId): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT COUNT(*) FROM files f
            LEFT JOIN file_shares fs ON f.file_id = fs.file_id
            WHERE f.file_id = ? 
            AND (f.user_id = ? OR fs.shared_with = ?)
            AND (fs.expires_at IS NULL OR fs.expires_at > NOW())
        ");
        $stmt->execute([$fileId, $userId, $userId]);
        
        return $stmt->fetchColumn() > 0;
    }

    /**
     * Check if file has expired
     */
    private function isFileExpired(string $fileId): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT expires_at FROM files WHERE file_id = ?
        ");
        $stmt->execute([$fileId]);
        $file = $stmt->fetch();
        
        if (!$file || !$file['expires_at']) {
            return false;
        }
        
        return strtotime($file['expires_at']) < time();
    }

    /**
     * Check if user owns the file
     */
    private function isFileOwner(string $fileId, string $userId): bool
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT COUNT(*) FROM files WHERE file_id = ? AND user_id = ?
        ");
        $stmt->execute([$fileId, $userId]);
        
        return $stmt->fetchColumn() > 0;
    }

    /**
     * Generate unique file ID
     */
    private function generateFileId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Calculate expiry time
     */
    private function calculateExpiryTime(int $hours): string
    {
        return date('Y-m-d H:i:s', time() + ($hours * 3600));
    }

    /**
     * Store file metadata in database
     */
    private function storeFileMetadata(string $fileId, string $userId, array $file, array $encryptionResult, array $watermarkResult): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            INSERT INTO files (
                file_id, user_id, original_name, encrypted_name, file_size, 
                encrypted_size, mime_type, file_hash, encrypted_file_key,
                watermark_data, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $expiryHours = $_POST['expiry_hours'] ?? 24;
        $expiresAt = $this->calculateExpiryTime($expiryHours);
        
        $stmt->execute([
            $fileId,
            $userId,
            $file['name'],
            $encryptionResult['encrypted_name'],
            $encryptionResult['file_size'],
            $encryptionResult['encrypted_size'],
            $encryptionResult['mime_type'],
            $encryptionResult['file_hash'],
            $encryptionResult['encrypted_file_key'],
            json_encode($watermarkResult['watermark_data']),
            $expiresAt
        ]);
    }

    /**
     * Get file metadata
     */
    private function getFileMetadata(string $fileId): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT original_name, mime_type, file_size, created_at
            FROM files WHERE file_id = ?
        ");
        $stmt->execute([$fileId]);
        
        return $stmt->fetch();
    }

    /**
     * Create file share record
     */
    private function createFileShare(string $fileId, string $userId, array $input): string
    {
        $db = $this->app->getDatabase();
        $shareId = $this->generateFileId();
        
        $stmt = $db->prepare("
            INSERT INTO file_shares (
                share_id, file_id, shared_by, shared_with, permissions,
                expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $expiresAt = $this->calculateExpiryTime($input['expiry_hours'] ?? 24);
        
        $stmt->execute([
            $shareId,
            $fileId,
            $userId,
            $input['shared_with'],
            $input['permissions'] ?? 'read',
            $expiresAt
        ]);
        
        return $shareId;
    }

    /**
     * Revoke file shares
     */
    private function revokeFileShares(string $fileId): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            UPDATE file_shares 
            SET is_revoked = 1, revoked_at = NOW()
            WHERE file_id = ? AND is_revoked = 0
        ");
        $stmt->execute([$fileId]);
    }

    /**
     * Get user files
     */
    private function getUserFiles(string $userId): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT file_id, original_name, file_size, mime_type, 
                   created_at, expires_at, is_expired
            FROM files 
            WHERE user_id = ?
            ORDER BY created_at DESC
        ");
        $stmt->execute([$userId]);
        
        return $stmt->fetchAll();
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


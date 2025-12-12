<?php

namespace SecureFileShare\Security;

use Intervention\Image\ImageManager;
use Intervention\Image\Drivers\Gd\Driver;
use SecureFileShare\Core\Application;

class WatermarkManager
{
    private $app;
    private $watermarkPath;
    private $imageManager;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->watermarkPath = $this->app->getConfig('watermark_path');
        $this->imageManager = new ImageManager(new Driver());
        
        $this->ensureDirectoriesExist();
    }

    /**
     * Add digital watermark to file
     */
    public function addWatermark(string $filePath, string $userId, string $fileId): array
    {
        $fileInfo = pathinfo($filePath);
        $extension = strtolower($fileInfo['extension']);
        
        // Generate unique watermark data
        $watermarkData = $this->generateWatermarkData($userId, $fileId);
        
        switch ($extension) {
            case 'jpg':
            case 'jpeg':
            case 'png':
            case 'gif':
                return $this->watermarkImage($filePath, $watermarkData);
            
            case 'pdf':
                return $this->watermarkPdf($filePath, $watermarkData);
            
            case 'doc':
            case 'docx':
                return $this->watermarkDocument($filePath, $watermarkData);
            
            default:
                return $this->watermarkGeneric($filePath, $watermarkData);
        }
    }

    /**
     * Watermark image files
     */
    private function watermarkImage(string $filePath, array $watermarkData): array
    {
        try {
            $image = $this->imageManager->read($filePath);
            
            // Add invisible watermark (steganography)
            $this->addSteganographicWatermark($image, $watermarkData);
            
            // Add visible watermark for deterrence
            $this->addVisibleWatermark($image, $watermarkData);
            
            // Save watermarked image
            $watermarkedPath = $this->watermarkPath . 'watermarked_' . basename($filePath);
            $image->save($watermarkedPath);
            
            return [
                'watermarked_path' => $watermarkedPath,
                'watermark_data' => $watermarkData,
                'watermark_type' => 'image'
            ];
            
        } catch (\Exception $e) {
            $this->app->getLogger()->error("Image watermarking failed: " . $e->getMessage());
            throw new \Exception("Image watermarking failed");
        }
    }

    /**
     * Add steganographic watermark to image
     */
    private function addSteganographicWatermark($image, array $watermarkData): void
    {
        // Convert watermark data to binary
        $watermarkBinary = $this->dataToBinary($watermarkData);
        
        // Get image dimensions
        $width = $image->width();
        $height = $image->height();
        
        // Embed watermark in LSB of pixels
        $pixelIndex = 0;
        for ($y = 0; $y < $height && $pixelIndex < strlen($watermarkBinary); $y++) {
            for ($x = 0; $x < $width && $pixelIndex < strlen($watermarkBinary); $x++) {
                $pixel = $image->pickColor($x, $y);
                
                // Modify LSB of red channel
                $red = $pixel[0];
                $newRed = ($red & 0xFE) | (int)$watermarkBinary[$pixelIndex];
                
                $image->pixel($newRed, $pixel[1], $pixel[2], $x, $y);
                $pixelIndex++;
            }
        }
    }

    /**
     * Add visible watermark to image
     */
    private function addVisibleWatermark($image, array $watermarkData): void
    {
        $text = "ID: {$watermarkData['file_id']} | User: {$watermarkData['user_id']} | " . date('Y-m-d H:i:s');
        
        // Add semi-transparent text watermark
        $image->text($text, $image->width() - 10, $image->height() - 10, function ($font) {
            $font->filename(__DIR__ . '/../../assets/fonts/arial.ttf');
            $font->size(12);
            $font->color('rgba(255, 255, 255, 0.7)');
            $font->align('right');
            $font->valign('bottom');
        });
    }

    /**
     * Watermark PDF files
     */
    private function watermarkPdf(string $filePath, array $watermarkData): array
    {
        // For PDF watermarking, we'll add metadata and create a fingerprint
        $watermarkText = $this->generateWatermarkText($watermarkData);
        
        // Create watermarked PDF path
        $watermarkedPath = $this->watermarkPath . 'watermarked_' . basename($filePath);
        
        // Copy original file (PDF watermarking requires specialized libraries)
        copy($filePath, $watermarkedPath);
        
        // Add watermark as metadata (this is a simplified approach)
        $this->addPdfMetadata($watermarkedPath, $watermarkData);
        
        return [
            'watermarked_path' => $watermarkedPath,
            'watermark_data' => $watermarkData,
            'watermark_type' => 'pdf',
            'watermark_text' => $watermarkText
        ];
    }

    /**
     * Watermark document files
     */
    private function watermarkDocument(string $filePath, array $watermarkData): array
    {
        $watermarkText = $this->generateWatermarkText($watermarkData);
        
        // For document files, we'll create a fingerprint in the filename and metadata
        $fileInfo = pathinfo($filePath);
        $watermarkedPath = $this->watermarkPath . 
            'watermarked_' . $fileInfo['filename'] . '_' . substr($watermarkData['file_id'], 0, 8) . 
            '.' . $fileInfo['extension'];
        
        copy($filePath, $watermarkedPath);
        
        return [
            'watermarked_path' => $watermarkedPath,
            'watermark_data' => $watermarkData,
            'watermark_type' => 'document',
            'watermark_text' => $watermarkText
        ];
    }

    /**
     * Watermark generic files
     */
    private function watermarkGeneric(string $filePath, array $watermarkData): array
    {
        $watermarkText = $this->generateWatermarkText($watermarkData);
        
        // For generic files, create a fingerprint file
        $fingerprintPath = $this->watermarkPath . 'fingerprint_' . $watermarkData['file_id'] . '.txt';
        file_put_contents($fingerprintPath, $watermarkText);
        
        return [
            'watermarked_path' => $filePath,
            'fingerprint_path' => $fingerprintPath,
            'watermark_data' => $watermarkData,
            'watermark_type' => 'generic',
            'watermark_text' => $watermarkText
        ];
    }

    /**
     * Generate watermark data
     */
    private function generateWatermarkData(string $userId, string $fileId): array
    {
        return [
            'file_id' => $fileId,
            'user_id' => $userId,
            'timestamp' => time(),
            'session_id' => session_id(),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'checksum' => hash('sha256', $fileId . $userId . time())
        ];
    }

    /**
     * Generate watermark text
     */
    private function generateWatermarkText(array $watermarkData): string
    {
        return sprintf(
            "SECURE FILE SHARING SYSTEM\n" .
            "File ID: %s\n" .
            "User ID: %s\n" .
            "Timestamp: %s\n" .
            "Session: %s\n" .
            "IP: %s\n" .
            "Checksum: %s\n" .
            "This file is protected by digital watermarking.\n" .
            "Unauthorized distribution is monitored and logged.",
            $watermarkData['file_id'],
            $watermarkData['user_id'],
            date('Y-m-d H:i:s', $watermarkData['timestamp']),
            $watermarkData['session_id'],
            $watermarkData['ip_address'],
            $watermarkData['checksum']
        );
    }

    /**
     * Convert data to binary string
     */
    private function dataToBinary(array $data): string
    {
        $json = json_encode($data);
        $binary = '';
        
        for ($i = 0; $i < strlen($json); $i++) {
            $binary .= sprintf('%08b', ord($json[$i]));
        }
        
        return $binary;
    }

    /**
     * Add metadata to PDF (simplified approach)
     */
    private function addPdfMetadata(string $filePath, array $watermarkData): void
    {
        // This is a simplified approach. In production, you'd use a proper PDF library
        $metadata = $this->generateWatermarkText($watermarkData);
        
        // Create a metadata file alongside the PDF
        $metadataPath = $filePath . '.metadata';
        file_put_contents($metadataPath, $metadata);
    }

    /**
     * Detect watermark in file
     */
    public function detectWatermark(string $filePath): ?array
    {
        $fileInfo = pathinfo($filePath);
        $extension = strtolower($fileInfo['extension']);
        
        if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif'])) {
            return $this->detectImageWatermark($filePath);
        }
        
        return null;
    }

    /**
     * Detect watermark in image
     */
    private function detectImageWatermark(string $filePath): ?array
    {
        try {
            $image = $this->imageManager->read($filePath);
            $width = $image->width();
            $height = $image->height();
            
            // Extract LSB data
            $binaryData = '';
            for ($y = 0; $y < $height; $y++) {
                for ($x = 0; $x < $width; $x++) {
                    $pixel = $image->pickColor($x, $y);
                    $binaryData .= $pixel[0] & 1;
                }
            }
            
            // Convert binary back to data
            $watermarkData = $this->binaryToData($binaryData);
            
            return $watermarkData;
            
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Convert binary string back to data
     */
    private function binaryToData(string $binary): ?array
    {
        if (strlen($binary) % 8 !== 0) {
            return null;
        }
        
        $json = '';
        for ($i = 0; $i < strlen($binary); $i += 8) {
            $byte = substr($binary, $i, 8);
            $json .= chr(bindec($byte));
        }
        
        return json_decode($json, true);
    }

    /**
     * Ensure required directories exist
     */
    private function ensureDirectoriesExist(): void
    {
        if (!is_dir($this->watermarkPath)) {
            mkdir($this->watermarkPath, 0755, true);
        }
    }

    /**
     * Generate file fingerprint for tracking
     */
    public function generateFileFingerprint(string $filePath, array $watermarkData): string
    {
        $fileContent = file_get_contents($filePath);
        $fileHash = hash('sha256', $fileContent);
        
        $fingerprintData = [
            'file_hash' => $fileHash,
            'watermark_data' => $watermarkData,
            'file_size' => filesize($filePath),
            'created_at' => date('Y-m-d H:i:s')
        ];
        
        return hash('sha256', json_encode($fingerprintData));
    }
}


<?php

namespace SecureFileShare\Security;

use SecureFileShare\Core\Application;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogHandler;

class MonitoringManager
{
    private $app;
    private $logger;
    private $auditLogger;
    private $securityLogger;

    public function __construct()
    {
        $this->app = Application::getInstance();
        $this->initializeLoggers();
    }

    /**
     * Initialize different loggers for different purposes
     */
    private function initializeLoggers(): void
    {
        // General application logger
        $this->logger = new Logger('app');
        $this->logger->pushHandler(new StreamHandler(__DIR__ . '/../../logs/app.log', Logger::INFO));

        // Audit logger for compliance
        $this->auditLogger = new Logger('audit');
        $this->auditLogger->pushHandler(new StreamHandler(__DIR__ . '/../../logs/audit.log', Logger::INFO));
        $this->auditLogger->pushHandler(new SyslogHandler('secure-file-share', LOG_USER, Logger::INFO));

        // Security logger for threats
        $this->securityLogger = new Logger('security');
        $this->securityLogger->pushHandler(new StreamHandler(__DIR__ . '/../../logs/security.log', Logger::WARNING));
    }

    /**
     * Log file access event
     */
    public function logFileAccess(string $fileId, string $userId, string $action, array $metadata = []): void
    {
        $event = [
            'event_type' => 'file_access',
            'file_id' => $fileId,
            'user_id' => $userId,
            'action' => $action,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id(),
            'metadata' => $metadata
        ];

        $this->auditLogger->info('File access event', $event);
        $this->storeEventInDatabase($event);
    }

    /**
     * Log authentication event
     */
    public function logAuthentication(string $userId, string $action, bool $success, array $metadata = []): void
    {
        $event = [
            'event_type' => 'authentication',
            'user_id' => $userId,
            'action' => $action,
            'success' => $success,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id(),
            'metadata' => $metadata
        ];

        $level = $success ? Logger::INFO : Logger::WARNING;
        $this->auditLogger->log($level, 'Authentication event', $event);
        $this->storeEventInDatabase($event);
    }

    /**
     * Log security threat
     */
    public function logSecurityThreat(string $threatType, string $description, array $metadata = []): void
    {
        $event = [
            'event_type' => 'security_threat',
            'threat_type' => $threatType,
            'description' => $description,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id(),
            'metadata' => $metadata
        ];

        $this->securityLogger->error('Security threat detected', $event);
        $this->storeEventInDatabase($event);
        $this->triggerSecurityAlert($event);
    }

    /**
     * Log file sharing event
     */
    public function logFileSharing(string $fileId, string $fromUserId, string $toUserId, array $metadata = []): void
    {
        $event = [
            'event_type' => 'file_sharing',
            'file_id' => $fileId,
            'from_user_id' => $fromUserId,
            'to_user_id' => $toUserId,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id(),
            'metadata' => $metadata
        ];

        $this->auditLogger->info('File sharing event', $event);
        $this->storeEventInDatabase($event);
    }

    /**
     * Log system event
     */
    public function logSystemEvent(string $eventType, string $description, array $metadata = []): void
    {
        $event = [
            'event_type' => $eventType,
            'description' => $description,
            'timestamp' => date('Y-m-d H:i:s'),
            'metadata' => $metadata
        ];

        $this->logger->info('System event', $event);
        $this->storeEventInDatabase($event);
    }

    /**
     * Monitor real-time activities
     */
    public function monitorRealTimeActivity(): array
    {
        $db = $this->app->getDatabase();
        
        // Get recent activities (last 5 minutes)
        $stmt = $db->prepare("
            SELECT * FROM audit_logs 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
            ORDER BY created_at DESC
            LIMIT 100
        ");
        $stmt->execute();
        
        return $stmt->fetchAll();
    }

    /**
     * Detect suspicious activities
     */
    public function detectSuspiciousActivity(): array
    {
        $db = $this->app->getDatabase();
        $suspiciousActivities = [];

        // Check for multiple failed login attempts
        $stmt = $db->prepare("
            SELECT user_id, COUNT(*) as attempts, ip_address
            FROM audit_logs 
            WHERE event_type = 'authentication' 
            AND JSON_EXTRACT(metadata, '$.success') = false
            AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            GROUP BY user_id, ip_address
            HAVING attempts >= 5
        ");
        $stmt->execute();
        $failedLogins = $stmt->fetchAll();

        foreach ($failedLogins as $login) {
            $suspiciousActivities[] = [
                'type' => 'multiple_failed_logins',
                'user_id' => $login['user_id'],
                'ip_address' => $login['ip_address'],
                'attempts' => $login['attempts'],
                'severity' => 'high'
            ];
        }

        // Check for unusual file access patterns
        $stmt = $db->prepare("
            SELECT user_id, COUNT(*) as access_count, ip_address
            FROM audit_logs 
            WHERE event_type = 'file_access' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY user_id, ip_address
            HAVING access_count >= 50
        ");
        $stmt->execute();
        $unusualAccess = $stmt->fetchAll();

        foreach ($unusualAccess as $access) {
            $suspiciousActivities[] = [
                'type' => 'unusual_file_access',
                'user_id' => $access['user_id'],
                'ip_address' => $access['ip_address'],
                'access_count' => $access['access_count'],
                'severity' => 'medium'
            ];
        }

        // Check for access from multiple IPs
        $stmt = $db->prepare("
            SELECT user_id, COUNT(DISTINCT ip_address) as ip_count
            FROM audit_logs 
            WHERE event_type = 'authentication' 
            AND JSON_EXTRACT(metadata, '$.success') = true
            AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY user_id
            HAVING ip_count >= 3
        ");
        $stmt->execute();
        $multipleIPs = $stmt->fetchAll();

        foreach ($multipleIPs as $ip) {
            $suspiciousActivities[] = [
                'type' => 'multiple_ip_access',
                'user_id' => $ip['user_id'],
                'ip_count' => $ip['ip_count'],
                'severity' => 'medium'
            ];
        }

        return $suspiciousActivities;
    }

    /**
     * Generate security report
     */
    public function generateSecurityReport(string $startDate, string $endDate): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT 
                event_type,
                COUNT(*) as event_count,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT ip_address) as unique_ips
            FROM audit_logs 
            WHERE created_at BETWEEN ? AND ?
            GROUP BY event_type
        ");
        $stmt->execute([$startDate, $endDate]);
        
        $report = [
            'period' => ['start' => $startDate, 'end' => $endDate],
            'summary' => $stmt->fetchAll(),
            'threats' => $this->getThreatsInPeriod($startDate, $endDate),
            'top_users' => $this->getTopUsersInPeriod($startDate, $endDate),
            'top_files' => $this->getTopFilesInPeriod($startDate, $endDate)
        ];
        
        return $report;
    }

    /**
     * Store event in database
     */
    private function storeEventInDatabase(array $event): void
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            INSERT INTO audit_logs (
                event_type, user_id, action, success, description, 
                ip_address, user_agent, session_id, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ");
        
        $stmt->execute([
            $event['event_type'],
            $event['user_id'] ?? null,
            $event['action'] ?? null,
            $event['success'] ?? null,
            $event['description'] ?? null,
            $event['ip_address'],
            $event['user_agent'],
            $event['session_id'],
            json_encode($event['metadata'] ?? [])
        ]);
    }

    /**
     * Trigger security alert
     */
    private function triggerSecurityAlert(array $event): void
    {
        // Log to security log
        $this->securityLogger->critical('Security alert triggered', $event);
        
        // In production, you would:
        // - Send email alerts to administrators
        // - Send SMS notifications
        // - Integrate with SIEM systems
        // - Trigger automated responses
        
        $this->app->getLogger()->warning('Security alert: ' . $event['description']);
    }

    /**
     * Get threats in period
     */
    private function getThreatsInPeriod(string $startDate, string $endDate): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT threat_type, COUNT(*) as count, MAX(created_at) as last_occurrence
            FROM audit_logs 
            WHERE event_type = 'security_threat' 
            AND created_at BETWEEN ? AND ?
            GROUP BY threat_type
            ORDER BY count DESC
        ");
        $stmt->execute([$startDate, $endDate]);
        
        return $stmt->fetchAll();
    }

    /**
     * Get top users in period
     */
    private function getTopUsersInPeriod(string $startDate, string $endDate): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT user_id, COUNT(*) as activity_count
            FROM audit_logs 
            WHERE user_id IS NOT NULL 
            AND created_at BETWEEN ? AND ?
            GROUP BY user_id
            ORDER BY activity_count DESC
            LIMIT 10
        ");
        $stmt->execute([$startDate, $endDate]);
        
        return $stmt->fetchAll();
    }

    /**
     * Get top files in period
     */
    private function getTopFilesInPeriod(string $startDate, string $endDate): array
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            SELECT JSON_EXTRACT(metadata, '$.file_id') as file_id, COUNT(*) as access_count
            FROM audit_logs 
            WHERE event_type = 'file_access' 
            AND created_at BETWEEN ? AND ?
            GROUP BY file_id
            ORDER BY access_count DESC
            LIMIT 10
        ");
        $stmt->execute([$startDate, $endDate]);
        
        return $stmt->fetchAll();
    }

    /**
     * Clean old audit logs
     */
    public function cleanOldLogs(int $daysToKeep = 90): int
    {
        $db = $this->app->getDatabase();
        
        $stmt = $db->prepare("
            DELETE FROM audit_logs 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)
        ");
        $stmt->execute([$daysToKeep]);
        
        return $stmt->rowCount();
    }
}


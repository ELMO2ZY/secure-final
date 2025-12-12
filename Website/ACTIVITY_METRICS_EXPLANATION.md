# Activity Metrics Explanation
## How "High Risk" and "Access Denied" Work

---

## Overview

The Activity Log tracks all security events and calculates two important metrics:
- **High Risk**: Critical security events that need immediate attention
- **Access Denied**: All failed access attempts and security violations

---

## How It Works

### 1. Activity Logging System

Every action in the system is logged using the `logActivity()` function with these parameters:
- `eventType`: Type of event (authentication, file_upload, file_download, etc.)
- `action`: Specific action (login, upload, download, delete)
- `fileId`: ID of the file (if applicable)
- `fileName`: Name of the file (if applicable)
- `userId`: ID of the user performing the action
- `success`: Whether the action succeeded (true/false)
- `description`: Human-readable description
- `riskLevel`: Risk level ('low', 'medium', or 'high')

### 2. Risk Level Classification

#### **Low Risk** (Green)
Normal, successful operations:
- ✅ Successful login
- ✅ Successful file upload
- ✅ Successful file download
- ✅ Successful file deletion

**Example:**
```php
logActivity('file_upload', 'upload', $fileId, $fileName, $userId, true, "File uploaded: {$fileName}", 'low');
```

#### **Medium Risk** (Yellow)
Operations that failed but aren't critical:
- ⚠️ File not found
- ⚠️ File deletion (requires attention but not critical)

**Example:**
```php
logActivity('file_access', 'download', $fileId, 'Unknown File', $userId, false, "File not found: {$fileId}", 'medium');
```

#### **High Risk** (Red)
Critical security events requiring immediate attention:
- 🚨 **Failed login attempts** - Someone trying to access with wrong credentials
- 🚨 **Expired file access** - Attempting to access files that have expired
- 🚨 **Permission denied** - Unauthorized access attempts

**Examples:**
```php
// Failed login
logActivity('authentication', 'login', null, null, null, false, "Failed login attempt for: {$email}", 'high');

// Expired file access
logActivity('file_access', 'download', $fileId, $file['name'], $userId, false, "File expired: {$file['name']}", 'high');

// Permission denied
logActivity('access_denied', 'download', $fileId, $file['name'], $userId, false, "Access denied: Insufficient permissions", 'high');
```

---

## How Metrics Are Calculated

### **High Risk Count**
Counts all events where `risk_level === 'high'`:

```php
if ($riskLevel === 'high') {
    $stats['high_risk']++;
}
```

**Includes:**
- Failed login attempts
- Expired file access attempts
- Permission denied attempts

### **Access Denied Count**
Counts all events where the operation failed OR is high risk:

```php
if (!$success || $riskLevel === 'high') {
    $stats['access_denied']++;
}
```

**Includes:**
- All high risk events (failed logins, expired files, permission denied)
- Any failed operation (success = false)
- File not found errors
- Any other unsuccessful attempts

---

## Real-World Scenarios

### Scenario 1: Failed Login Attempt
**What happens:**
1. User enters wrong password: `admin@securefileshare.com` / `wrongpassword`
2. System logs: `logActivity('authentication', 'login', null, null, null, false, "Failed login attempt...", 'high')`
3. **High Risk**: +1
4. **Access Denied**: +1

### Scenario 2: Expired File Access
**What happens:**
1. User tries to download a file that expired 2 days ago
2. System logs: `logActivity('file_access', 'download', $fileId, $fileName, $userId, false, "File expired...", 'high')`
3. **High Risk**: +1
4. **Access Denied**: +1

### Scenario 3: Permission Denied
**What happens:**
1. A "viewer" user tries to upload a file (they only have download permission)
2. System logs: `logActivity('access_denied', 'upload', null, null, $userId, false, "Access denied: Insufficient permissions", 'high')`
3. **High Risk**: +1
4. **Access Denied**: +1

### Scenario 4: File Not Found
**What happens:**
1. User tries to download a file that doesn't exist
2. System logs: `logActivity('file_access', 'download', $fileId, 'Unknown File', $userId, false, "File not found...", 'medium')`
3. **High Risk**: +0 (medium risk, not high)
4. **Access Denied**: +1 (because success = false)

### Scenario 5: Successful Operations
**What happens:**
1. User successfully uploads a file
2. System logs: `logActivity('file_upload', 'upload', $fileId, $fileName, $userId, true, "File uploaded...", 'low')`
3. **High Risk**: +0
4. **Access Denied**: +0

---

## Code Locations

### Where Events Are Logged:

1. **Login (api.php:122, 139)**
   - Success: `logActivity(..., true, ..., 'low')`
   - Failure: `logActivity(..., false, ..., 'high')`

2. **File Upload (api.php:180)**
   - Success: `logActivity('file_upload', 'upload', ..., true, ..., 'low')`

3. **File Download (api.php:209, 218, 225, 231)**
   - File not found: `logActivity(..., false, ..., 'medium')`
   - File expired: `logActivity(..., false, ..., 'high')`
   - Permission denied: `logActivity(..., false, ..., 'high')`
   - Success: `logActivity(..., true, ..., 'low')`

4. **File Delete (api.php:318)**
   - Success: `logActivity('file_delete', 'delete', ..., true, ..., 'medium')`

### Where Metrics Are Calculated:

**Location:** `api.php` lines 490-510

```php
// Calculate statistics from all logs
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
```

---

## Summary

| Event Type | Success | Risk Level | High Risk | Access Denied |
|------------|---------|------------|-----------|---------------|
| Successful Login | ✅ true | low | ❌ No | ❌ No |
| Failed Login | ❌ false | **high** | ✅ **Yes** | ✅ **Yes** |
| Successful Upload | ✅ true | low | ❌ No | ❌ No |
| Successful Download | ✅ true | low | ❌ No | ❌ No |
| File Not Found | ❌ false | medium | ❌ No | ✅ **Yes** |
| File Expired | ❌ false | **high** | ✅ **Yes** | ✅ **Yes** |
| Permission Denied | ❌ false | **high** | ✅ **Yes** | ✅ **Yes** |

---

## Key Points

1. **High Risk** = Only critical security events (failed logins, expired files, permission denied)
2. **Access Denied** = Any failed operation (includes high risk + other failures)
3. **All metrics are calculated from real activity logs** - no fake data
4. **Metrics update automatically** as events occur
5. **Activity logs are stored in PHP sessions** - no database needed

---

## Testing the Metrics

To see the metrics in action:

1. **Test High Risk:**
   - Try logging in with wrong password → High Risk +1, Access Denied +1
   - Try downloading an expired file → High Risk +1, Access Denied +1

2. **Test Access Denied:**
   - Try accessing a non-existent file → Access Denied +1 (but not High Risk)
   - Try uploading without permission → High Risk +1, Access Denied +1

3. **Test Normal Operations:**
   - Login successfully → No change
   - Upload a file → No change (successful operations don't count as denied/risk)

The numbers you see are **100% real** and based on actual events in your system!





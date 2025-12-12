# Secure File Sharing API Documentation

## Overview
This API provides secure file sharing capabilities with end-to-end encryption, digital watermarking, and comprehensive monitoring.

## Authentication
All API endpoints require authentication via JWT Bearer token, except for login and registration.

### Headers
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

## Endpoints

### Authentication

#### POST /api/auth/login
Login with email and password.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "token": "jwt_token_here",
        "user": {
            "id": "user_id",
            "email": "user@example.com",
            "role": "user"
        },
        "message": "Login successful"
    }
}
```

#### POST /api/auth/register
Register a new user account.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "password123",
    "confirm_password": "password123",
    "first_name": "John",
    "last_name": "Doe"
}
```

#### POST /api/auth/verify-2fa
Verify two-factor authentication code.

**Request Body:**
```json
{
    "email": "user@example.com",
    "code": "123456",
    "two_factor_token": "token_from_login"
}
```

### File Management

#### POST /api/files/upload
Upload a file with encryption and watermarking.

**Request:** Multipart form data
- `file`: The file to upload
- `expiry_hours`: Hours until file expires (default: 24)

**Response:**
```json
{
    "success": true,
    "data": {
        "file_id": "unique_file_id",
        "message": "File uploaded successfully",
        "expires_at": "2024-01-01 12:00:00"
    }
}
```

#### GET /api/files/download/{fileId}
Download a file (decrypted).

**Response:** File download with appropriate headers.

#### POST /api/files/share/{fileId}
Share a file with another user.

**Request Body:**
```json
{
    "shared_with": "user_id_or_email",
    "expiry_hours": 24,
    "permissions": "read"
}
```

#### DELETE /api/files/revoke/{fileId}
Revoke access to a shared file.

#### DELETE /api/files/delete/{fileId}
Permanently delete a file.

#### GET /api/files/list
Get list of user's files.

**Response:**
```json
{
    "success": true,
    "data": {
        "files": [
            {
                "file_id": "file_id",
                "original_name": "document.pdf",
                "file_size": 1024000,
                "mime_type": "application/pdf",
                "created_at": "2024-01-01 10:00:00",
                "expires_at": "2024-01-02 10:00:00"
            }
        ]
    }
}
```

## Security Features

### Encryption
- All files are encrypted using AES-256 before storage
- Each file has a unique encryption key
- User-specific master keys protect file keys

### Digital Watermarking
- Invisible steganographic watermarks in images
- Visible watermarks for deterrence
- Metadata watermarks for documents
- Unique fingerprints for tracking

### Access Control
- Role-based permissions (admin, user, viewer)
- File-level access control
- Time-based access expiration
- Share revocation capabilities

### Monitoring
- Real-time activity monitoring
- Comprehensive audit logging
- Suspicious activity detection
- Security threat alerts

### API Security
- Rate limiting (60 requests/minute)
- CSRF protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection

## Error Responses

All error responses follow this format:
```json
{
    "success": false,
    "error": "Error message",
    "code": 400,
    "timestamp": "2024-01-01 12:00:00"
}
```

### Common Error Codes
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (authentication required)
- `403`: Forbidden (access denied)
- `404`: Not Found (route/file not found)
- `409`: Conflict (user already exists)
- `410`: Gone (file expired)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

## Rate Limits
- 60 requests per minute per IP address
- File uploads: 100MB maximum
- Session timeout: 30 minutes

## File Types
Supported file types: pdf, doc, docx, txt, jpg, jpeg, png

## Security Headers
The API automatically sets security headers:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security: max-age=31536000
- Content-Security-Policy: default-src 'self'


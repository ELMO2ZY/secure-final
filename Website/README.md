# Secure File Sharing System

A beautiful, secure file sharing application with AES-256 encryption, JWT authentication, and role-based access control.

## 🚀 Quick Start

1. **Set up the database** (see Installation section below)
2. **Configure environment variables** (copy `env.example` to `.env` and edit)
3. **Create your first admin user** using `setup_admin.php`
4. **Open `login.html`** in your browser to start using the application

See `MIGRATION_GUIDE.md` for detailed setup instructions.

## 📁 File Structure

### Frontend Files
- **`frontend.html`** - Main application interface (standalone HTML/CSS/JS)
- **`demo.php`** - Beautiful landing page showcasing features
- **`security_tests.php`** - Comprehensive security testing page

### Backend Files
- **`api.php`** - Clean PHP API backend with database integration
- **`config.php`** - Configuration loader for database and environment variables
- **`setup_admin.php`** - Script to create the first admin user
- **`index.php`** - Simple redirect to frontend

## ✨ Features

### 🔐 Security Features
- **AES-256-CBC encryption** for all files
- **JWT token authentication** with HMAC signatures
- **Role-based access control** (Admin/User/Viewer)
- **Password hashing** with bcrypt
- **Session management** with secure tokens
- **File expiry** (24 hours automatic)
- **Permission validation** for all operations
- **Secure random IV generation**
- **Comprehensive audit logging**

### 🎨 Frontend Features
- **Beautiful animations** and transitions
- **Glass-morphism design** with backdrop blur
- **Animated background particles**
- **Responsive design** for all devices
- **Modern gradient color scheme**
- **Interactive file upload** with drag & drop
- **Real-time notifications** and alerts
- **Professional UI** with security badges

## 🎯 User Roles & Permissions

### Admin
- Full access to all features
- Can upload, download, and manage all files
- Access to security tests and monitoring

### User
- Upload, download, and share files
- Manage own files
- View security features

### Viewer
- Download files only
- View file information
- Limited access to features

## 🛠️ Technical Details

### Backend (PHP)
- Clean separation of concerns
- RESTful API design
- Database-backed file storage
- JWT token system with database sessions
- AES-256 encryption/decryption
- Password hashing with bcrypt
- Comprehensive audit logging

### Frontend (HTML/CSS/JS)
- Standalone frontend (no PHP dependencies)
- Modern ES6+ JavaScript
- CSS3 animations and transitions
- Responsive grid layouts
- Fetch API for backend communication

## 🔧 Development Team

- **Mohamed Loai** - Backend Security Engineer
- **Khaled Sharaf** - Database Integration
- **Zayed Mohamed** - Frontend Developer
- **Youssef Mohamed** - UX/UI Designer & Product Manager
- **Mohamed Jamal** - Data Protection & Compliance Officer

## 📱 Pages

1. **`frontend.html`** - Main application
2. **`demo.php`** - Feature showcase
3. **`security_tests.php`** - Security validation
4. **`api.php`** - Backend API endpoints

## 📋 Installation

See `MIGRATION_GUIDE.md` for complete setup instructions. Quick steps:

1. **Database Setup**: Import `database/schema.sql` into MySQL
2. **Environment Config**: Copy `env.example` to `.env` and configure
3. **Create Admin**: Run `setup_admin.php` to create first admin user
4. **Storage**: Ensure `storage/uploads/` and `storage/encrypted/` directories exist

## 🎉 Ready to Use!

The application is **100% functional** with:
- ✅ Beautiful, modern UI
- ✅ Database-backed authentication system
- ✅ Secure password hashing
- ✅ File upload/download with encryption
- ✅ Role-based permissions from database
- ✅ Comprehensive audit logging
- ✅ Persistent file storage

**Start by setting up your database and creating an admin user!** 🚀
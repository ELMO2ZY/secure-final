# Login Troubleshooting Guide

## Important: You Must Use a Web Server

The login functionality requires PHP to run, which means you **cannot** open the HTML files directly in your browser (file:// protocol). You need to run a local web server.

## Quick Setup Instructions

### Option 1: PHP Built-in Server (Recommended)
1. Open a terminal/command prompt
2. Navigate to the project directory:
   ```
   cd "C:\Users\Dell\OneDrive\سطح المكتب\Website"
   ```
3. Start PHP server:
   ```
   php -S localhost:8000
   ```
4. Open your browser and go to:
   ```
   http://localhost:8000/login.html
   ```

### Option 2: Use XAMPP/WAMP
1. Install XAMPP or WAMP
2. Copy the project folder to `htdocs` (XAMPP) or `www` (WAMP)
3. Access via: `http://localhost/Website/login.html`

## Test Credentials

Use these demo accounts:

- **Admin:** `admin@securefileshare.com` / `admin123`
- **User:** `user@securefileshare.com` / `user123`
- **Viewer:** `viewer@securefileshare.com` / `viewer123`

## Debugging Steps

1. **Check Browser Console**
   - Press F12 to open Developer Tools
   - Go to Console tab
   - Look for error messages or the console.log outputs

2. **Test the API Directly**
   - Open `test_login.html` in your browser (via web server)
   - This will show you the raw API response

3. **Check if PHP is Working**
   - Visit: `http://localhost:8000/api.php` in your browser
   - You should see a JSON error (that's normal - it's expecting POST data)

## Common Issues

### Issue: "Login failed. Please check your connection"
- **Solution:** Make sure you're accessing via `http://localhost:8000` not `file://`
- Make sure PHP server is running

### Issue: No response from server
- **Solution:** Check that `api.php` exists in the same directory
- Verify PHP is installed and working

### Issue: "Invalid credentials" 
- **Solution:** Double-check you're using the exact email/password from above
- Email addresses are case-sensitive

### Issue: Form doesn't submit
- **Solution:** Open browser console (F12) and check for JavaScript errors
- Make sure all files are properly saved

## Still Having Issues?

1. Open browser console (F12)
2. Try to login
3. Look at the console messages - they will tell you exactly what's happening
4. Share those console messages for further help


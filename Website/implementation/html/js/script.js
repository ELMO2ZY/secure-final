// Simple interactive features
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scroll behavior
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Button click handlers
    const createAccountBtn = document.querySelector('.btn-create');
    const demoBtn = document.querySelector('.btn-demo');
    const startBtn = document.querySelector('.btn-start');

    if (createAccountBtn) {
        createAccountBtn.addEventListener('click', function() {
            console.log('Create Account clicked');
            // Add your account creation logic here
        });
    }

    if (demoBtn) {
        demoBtn.addEventListener('click', function() {
            console.log('View Demo clicked');
            // Add your demo logic here
        });
    }

    if (startBtn) {
        startBtn.addEventListener('click', function() {
            console.log('Start Now clicked');
            // Add your start logic here
        });
    }
});

// Toggle password visibility
function togglePassword(inputId = 'password') {
    const input = document.getElementById(inputId);
    if (input) {
        if (input.type === 'password') {
            input.type = 'text';
        } else {
            input.type = 'password';
        }
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${months[date.getMonth()]} ${date.getDate()}, ${date.getFullYear()}`;
}

// Calculate days until expiry
function getDaysUntilExpiry(expiresAt) {
    const expiryDate = new Date(expiresAt);
    const now = new Date();
    const diffTime = expiryDate - now;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
}

// Get file icon based on extension
function getFileIcon(fileName) {
    const ext = fileName.split('.').pop().toLowerCase();
    const iconSvg = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
        <polyline points="14 2 14 8 20 8"></polyline>
        <line x1="16" y1="13" x2="8" y2="13"></line>
        <line x1="16" y1="17" x2="8" y2="17"></line>
        <polyline points="10 9 9 9 8 9"></polyline>
    </svg>`;
    return iconSvg;
}

// Get current user info
function getCurrentUser() {
    try {
        const userStr = sessionStorage.getItem('user') || sessionStorage.getItem('currentUser');
        if (userStr) {
            return JSON.parse(userStr);
        }
    } catch (e) {
        console.error('Error parsing user data:', e);
    }
    return null;
}

// Check if user is admin
function isAdmin() {
    const user = getCurrentUser();
    return user && (user.role === 'admin' || (user.permissions && user.permissions.includes('all')));
}

// Render file item
function renderFileItem(file, isExpired = false) {
    const expiryDate = file.expires_at ? new Date(file.expires_at) : null;
    const isExpiredFile = isExpired || (expiryDate && expiryDate < new Date());
    const daysUntilExpiry = expiryDate ? getDaysUntilExpiry(file.expires_at) : null;
    const userIsAdmin = isAdmin();
    
    let fileHtml = `
        <div class="file-item" data-file-id="${file.file_id}">
            <div class="file-info" style="flex: 1;">
                ${isExpiredFile ? `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                    <span class="tag tag-expired">expired</span>
                    <div class="file-name">${file.name}</div>
                </div>` : `<div class="file-name">${file.name}</div>`}
                <div class="file-meta">${formatFileSize(file.size)} • Uploaded ${formatDate(file.uploaded_at)}</div>
                ${!isExpiredFile ? `
                <div class="file-tags">
                    <span class="tag tag-encrypted">Encrypted</span>
                    ${file.encrypted ? '<span class="tag tag-watermarked">Watermarked</span>' : ''}
                </div>
                ${daysUntilExpiry !== null && daysUntilExpiry > 0 ? `
                <div class="file-stats">
                    <span style="display: flex; align-items: center; gap: 4px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                            <line x1="16" y1="2" x2="16" y2="6"></line>
                            <line x1="8" y1="2" x2="8" y2="6"></line>
                            <line x1="3" y1="10" x2="21" y2="10"></line>
                        </svg>
                        Expires in ${daysUntilExpiry} ${daysUntilExpiry === 1 ? 'day' : 'days'}
                    </span>
                </div>
                ` : ''}
                ` : ''}
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                ${userIsAdmin ? `
                <div class="file-actions" style="display: flex; gap: 8px;">
                    <button class="file-action-btn" onclick="downloadFile('${file.file_id}', '${file.name.replace(/'/g, "\\'")}', false)" title="Download (Decrypted)">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                    </button>
                    <button class="file-action-btn file-action-encrypted" onclick="downloadFile('${file.file_id}', '${file.name.replace(/'/g, "\\'")}', true)" title="View Encrypted Version">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                    </button>
                    <button class="file-action-btn" onclick="editFile('${file.file_id}', '${file.name.replace(/'/g, "\\'")}', '${file.expires_at || ''}')" title="Edit">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                        </svg>
                    </button>
                    <button class="file-action-btn file-action-delete" onclick="deleteFile('${file.file_id}', '${file.name.replace(/'/g, "\\'")}')" title="Delete">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </div>
                ` : ''}
                <div class="file-icon">
                    ${getFileIcon(file.name)}
                </div>
            </div>
        </div>
    `;
    return fileHtml;
}

// Fetch files from API
async function fetchFiles() {
    try {
        // Get token from sessionStorage or localStorage (check multiple possible keys)
        const token = sessionStorage.getItem('user_token') || 
                     sessionStorage.getItem('auth_token') || 
                     sessionStorage.getItem('userToken') ||
                     localStorage.getItem('user_token') || 
                     localStorage.getItem('auth_token') ||
                     localStorage.getItem('userToken');
        
        if (!token) {
            console.error('No authentication token found');
            document.getElementById('active-files-container').innerHTML = `
                <div style="text-align: center; padding: 40px; color: #991b1b;">
                    <p>Please log in to view your files</p>
                </div>
            `;
            return;
        }

        // Create form data
        const formData = new FormData();
        formData.append('action', 'list_files');
        formData.append('token', token);

        // Fetch files from API
        const response = await fetch('../../api.php', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success && data.files) {
            displayFiles(data.files);
        } else {
            console.error('Failed to fetch files:', data.message);
            document.getElementById('active-files-container').innerHTML = `
                <div style="text-align: center; padding: 40px; color: #666;">
                    <p>${data.message || 'No files found'}</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error fetching files:', error);
        document.getElementById('active-files-container').innerHTML = `
            <div style="text-align: center; padding: 40px; color: #991b1b;">
                <p>Error loading files. Please try again later.</p>
            </div>
        `;
    }
}

// Display files
function displayFiles(files) {
    const activeFilesContainer = document.getElementById('active-files-container');
    const inactiveFilesContainer = document.getElementById('inactive-files-container');
    
    const now = new Date();
    const activeFiles = [];
    const expiredFiles = [];
    
    files.forEach(file => {
        const expiryDate = file.expires_at ? new Date(file.expires_at) : null;
        if (expiryDate && expiryDate < now) {
            expiredFiles.push(file);
        } else {
            activeFiles.push(file);
        }
    });

    // Update tab counts
    document.getElementById('active-count').textContent = activeFiles.length;
    document.getElementById('expired-count').textContent = expiredFiles.length;
    document.getElementById('revoked-count').textContent = '0';

    // Display active files
    if (activeFiles.length > 0) {
        activeFilesContainer.innerHTML = activeFiles.map(file => renderFileItem(file, false)).join('');
    } else {
        activeFilesContainer.innerHTML = `
            <div style="text-align: center; padding: 40px; color: #666;">
                <p>No active files. Upload a file to get started.</p>
            </div>
        `;
    }

    // Display expired files
    if (expiredFiles.length > 0) {
        inactiveFilesContainer.innerHTML = expiredFiles.map(file => renderFileItem(file, true)).join('');
    } else {
        inactiveFilesContainer.innerHTML = `
            <div style="text-align: center; padding: 40px; color: #666;">
                <p>No expired or revoked files</p>
            </div>
        `;
    }
}

// Download file
async function downloadFile(fileId, fileName, getEncrypted = false) {
    try {
        const token = sessionStorage.getItem('user_token') || 
                     sessionStorage.getItem('auth_token') || 
                     sessionStorage.getItem('userToken') ||
                     localStorage.getItem('user_token') || 
                     localStorage.getItem('auth_token') ||
                     localStorage.getItem('userToken');

        if (!token) {
            alert('Please log in to download files');
            return;
        }

        const formData = new FormData();
        formData.append('action', 'download');
        formData.append('token', token);
        formData.append('file_id', fileId);
        formData.append('get_encrypted', getEncrypted ? 'true' : 'false');

        const response = await fetch('../../api.php', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            // Decode base64 content and create download
            const binaryString = atob(result.content);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            const blob = new Blob([bytes]);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = result.file_name || fileName;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            if (getEncrypted) {
                showNotification('Encrypted file downloaded successfully', 'success');
            } else {
                showNotification('File downloaded successfully', 'success');
            }
        } else {
            alert(result.message || 'Download failed');
        }
    } catch (error) {
        console.error('Download error:', error);
        alert('Error downloading file. Please try again.');
    }
}

// Delete file
async function deleteFile(fileId, fileName) {
    if (!confirm(`Are you sure you want to delete "${fileName}"? This action cannot be undone.`)) {
        return;
    }

    try {
        const token = sessionStorage.getItem('user_token') || 
                     sessionStorage.getItem('auth_token') || 
                     sessionStorage.getItem('userToken') ||
                     localStorage.getItem('user_token') || 
                     localStorage.getItem('auth_token') ||
                     localStorage.getItem('userToken');

        if (!token) {
            alert('Please log in to delete files');
            return;
        }

        const formData = new FormData();
        formData.append('action', 'delete_file');
        formData.append('token', token);
        formData.append('file_id', fileId);

        const response = await fetch('../../api.php', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            showNotification('File deleted successfully', 'success');
            // Refresh the file list
            fetchFiles();
        } else {
            alert(result.message || 'Delete failed');
        }
    } catch (error) {
        console.error('Delete error:', error);
        alert('Error deleting file. Please try again.');
    }
}

// Close edit modal
function closeEditModal() {
    const modal = document.getElementById('edit-file-modal');
    if (modal) {
        modal.remove();
    }
}

// Edit file
function editFile(fileId, fileName, expiresAt) {
    // Calculate current expiry hours
    let currentExpiryHours = 24;
    if (expiresAt) {
        const expiryDate = new Date(expiresAt);
        const now = new Date();
        const diffHours = Math.ceil((expiryDate - now) / (1000 * 60 * 60));
        if (diffHours > 0) {
            currentExpiryHours = diffHours;
        }
    }

    // Remove any existing modal
    const existingModal = document.getElementById('edit-file-modal');
    if (existingModal) {
        existingModal.remove();
    }

    // Create edit modal
    const modal = document.createElement('div');
    modal.id = 'edit-file-modal';
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;';
    modal.innerHTML = `
        <div style="background: white; padding: 28px; border-radius: 12px; max-width: 500px; width: 90%; box-shadow: 0 10px 25px rgba(0,0,0,0.2);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
                <h3 style="margin: 0; font-size: 22px; font-weight: 600; color: #1a1a2e;">Edit File</h3>
                <button onclick="closeEditModal()" style="background: transparent; border: none; cursor: pointer; padding: 4px; color: #666; font-size: 20px; line-height: 1; transition: color 0.2s;" onmouseover="this.style.color='#1a1a2e'" onmouseout="this.style.color='#666'">×</button>
            </div>
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 8px; font-weight: 500; color: #374151; font-size: 14px;">File Name</label>
                <input type="text" id="edit-file-name" value="${fileName.replace(/"/g, '&quot;')}" style="width: 100%; padding: 10px 12px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 14px; transition: border-color 0.2s; box-sizing: border-box;" onfocus="this.style.borderColor='#3b82f6'; this.style.outline='none'" onblur="this.style.borderColor='#e5e7eb'">
            </div>
            <div style="margin-bottom: 24px;">
                <label style="display: block; margin-bottom: 8px; font-weight: 500; color: #374151; font-size: 14px;">Expiry (hours)</label>
                <input type="number" id="edit-expiry-hours" value="${currentExpiryHours}" min="1" style="width: 100%; padding: 10px 12px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 14px; transition: border-color 0.2s; box-sizing: border-box;" onfocus="this.style.borderColor='#3b82f6'; this.style.outline='none'" onblur="this.style.borderColor='#e5e7eb'">
            </div>
            <div style="display: flex; gap: 12px; justify-content: flex-end;">
                <button onclick="closeEditModal()" class="btn-cancel" style="padding: 10px 20px; border: 2px solid #e5e7eb; background: white; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; color: #374151; transition: all 0.2s;">Cancel</button>
                <button onclick="saveFileEdit('${fileId}')" class="btn-save" style="padding: 10px 20px; background: #065f46; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; box-shadow: 0 2px 4px rgba(6, 95, 70, 0.2);">Save Changes</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    
    // Close modal when clicking outside
    modal.addEventListener('click', function(e) {
        if (e.target === modal) {
            closeEditModal();
        }
    });
}

// Save file edit
async function saveFileEdit(fileId) {
    try {
        const newName = document.getElementById('edit-file-name').value.trim();
        const expiryHours = parseInt(document.getElementById('edit-expiry-hours').value);

        if (!newName) {
            alert('File name cannot be empty');
            return;
        }

        if (expiryHours < 1) {
            alert('Expiry must be at least 1 hour');
            return;
        }

        const token = sessionStorage.getItem('user_token') || 
                     sessionStorage.getItem('auth_token') || 
                     sessionStorage.getItem('userToken') ||
                     localStorage.getItem('user_token') || 
                     localStorage.getItem('auth_token') ||
                     localStorage.getItem('userToken');

        if (!token) {
            alert('Please log in to edit files');
            return;
        }

        const formData = new FormData();
        formData.append('action', 'update_file');
        formData.append('token', token);
        formData.append('file_id', fileId);
        formData.append('new_name', newName);
        formData.append('expiry_hours', expiryHours);

        const response = await fetch('../../api.php', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            // Close modal
            closeEditModal();
            // Show success message
            showNotification('File updated successfully', 'success');
            // Refresh the file list
            fetchFiles();
        } else {
            alert(result.message || 'Update failed');
        }
    } catch (error) {
        console.error('Edit error:', error);
        alert('Error updating file. Please try again.');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 14px 20px;
        background: ${type === 'success' ? '#065f46' : '#3b82f6'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        font-size: 14px;
        font-weight: 500;
        animation: slideIn 0.3s ease-out;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add CSS animations
if (!document.getElementById('notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
        .btn-cancel:hover {
            background: #f3f4f6 !important;
            border-color: #d1d5db !important;
            transform: translateY(-1px);
        }
        .btn-save:hover {
            background: #047857 !important;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(6, 95, 70, 0.3) !important;
        }
    `;
    document.head.appendChild(style);
}

// Load dashboard metrics
async function loadDashboardMetrics() {
    try {
        const token = sessionStorage.getItem('user_token') || 
                     sessionStorage.getItem('auth_token') || 
                     sessionStorage.getItem('userToken') ||
                     localStorage.getItem('user_token') || 
                     localStorage.getItem('auth_token') ||
                     localStorage.getItem('userToken');

        if (!token) {
            return;
        }

        const formData = new FormData();
        formData.append('action', 'list_files');
        formData.append('token', token);

        const response = await fetch('../../api.php', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success && data.files) {
            updateDashboardMetrics(data.files);
        }
    } catch (error) {
        console.error('Error loading dashboard metrics:', error);
    }
}

// Update dashboard metrics
function updateDashboardMetrics(files) {
    const now = new Date();
    const activeFiles = [];
    const expiredFiles = [];
    let expiringSoonCount = 0;
    let highRiskCount = 0;

    files.forEach(file => {
        const expiryDate = file.expires_at ? new Date(file.expires_at) : null;
        if (expiryDate) {
            if (expiryDate < now) {
                expiredFiles.push(file);
            } else {
                activeFiles.push(file);
                // Check if expiring in next 7 days
                const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
                if (daysUntilExpiry <= 7 && daysUntilExpiry > 0) {
                    expiringSoonCount++;
                }
            }
        } else {
            activeFiles.push(file);
        }
    });

    const totalFiles = files.length;
    const encryptedFiles = files.filter(f => f.encrypted).length;
    const encryptionRate = totalFiles > 0 ? Math.round((encryptedFiles / totalFiles) * 100) : 100;

    // Update metric values
    const encryptedCountEl = document.getElementById('encrypted-files-count');
    const encryptionRateEl = document.getElementById('encryption-rate');
    const activeFilesCountEl = document.getElementById('active-files-count');
    const totalFilesTextEl = document.getElementById('total-files-text');
    const highRiskCountEl = document.getElementById('high-risk-count');
    const securityEventsCountEl = document.getElementById('security-events-count');
    const alertsContainer = document.getElementById('security-alerts-container');

    if (encryptedCountEl) encryptedCountEl.textContent = encryptedFiles;
    if (encryptionRateEl) encryptionRateEl.textContent = `encryption rate ${encryptionRate}%`;
    if (activeFilesCountEl) activeFilesCountEl.textContent = activeFiles.length;
    if (totalFilesTextEl) totalFilesTextEl.textContent = `of ${totalFiles} total`;
    if (highRiskCountEl) highRiskCountEl.textContent = highRiskCount;
    if (securityEventsCountEl) securityEventsCountEl.textContent = totalFiles; // Using total files as events for now

    // Update security alerts
    if (alertsContainer) {
        let alertsHtml = '';
        
        if (expiringSoonCount > 0) {
            alertsHtml += `
                <div style="background: #fef3c7; padding: 18px; border-radius: 10px; display: flex; justify-content: space-between; align-items: flex-start; border-left: 4px solid #f59e0b; margin-bottom: 16px;">
                    <div style="flex: 1;">
                        <div style="font-weight: 600; margin-bottom: 6px; font-size: 14px; color: #92400e;">Files Expiring Soon</div>
                        <div style="font-size: 12px; color: #92400e; line-height: 1.4;">${expiringSoonCount} file${expiringSoonCount !== 1 ? 's' : ''} will expire in the next 7 days</div>
                    </div>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#92400e" stroke-width="2.5" style="flex-shrink: 0; margin-left: 12px;">
                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                        <line x1="16" y1="2" x2="16" y2="6"></line>
                        <line x1="8" y1="2" x2="8" y2="6"></line>
                        <line x1="3" y1="10" x2="21" y2="10"></line>
                    </svg>
                </div>
            `;
        }

        if (highRiskCount > 0) {
            alertsHtml += `
                <div style="background: #fee2e2; padding: 18px; border-radius: 10px; display: flex; justify-content: space-between; align-items: flex-start; border-left: 4px solid #dc2626; margin-bottom: 16px;">
                    <div style="flex: 1;">
                        <div style="font-weight: 600; margin-bottom: 6px; font-size: 14px; color: #991b1b;">High Risk Alerts</div>
                        <div style="font-size: 12px; color: #991b1b; line-height: 1.4;">${highRiskCount} security issue${highRiskCount !== 1 ? 's' : ''} requiring attention</div>
                    </div>
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#991b1b" stroke-width="2.5" style="flex-shrink: 0; margin-left: 12px;">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                </div>
            `;
        }

        if (alertsHtml === '') {
            alertsHtml = '<div style="text-align: center; padding: 20px; color: #666; font-size: 14px;">No security alerts at this time</div>';
        }

        alertsContainer.innerHTML = alertsHtml;
    }
}

// Load dashboard when dashboard.html page loads
if (window.location.pathname.includes('dashboard.html') || window.location.href.includes('dashboard.html')) {
    document.addEventListener('DOMContentLoaded', function() {
        loadDashboardMetrics();
        // Refresh metrics every 30 seconds
        setInterval(loadDashboardMetrics, 30000);
    });
}

// Load files when files.html page loads
if (window.location.pathname.includes('files.html')) {
    document.addEventListener('DOMContentLoaded', function() {
        fetchFiles();
    });
}


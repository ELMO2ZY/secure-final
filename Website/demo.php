<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Sharing Demo</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            min-height: 100vh;
            color: #333;
            overflow-x: hidden;
        }
        
        /* Animated background particles */
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 1;
        }
        
        .particle {
            position: absolute;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            animation: float 6s ease-in-out infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px) rotate(0deg); }
            50% { transform: translateY(-20px) rotate(180deg); }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
            z-index: 2;
        }
        
        .hero {
            text-align: center;
            padding: 80px 0;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 25px;
            margin-bottom: 40px;
            box-shadow: 0 30px 60px rgba(0,0,0,0.2);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: slideDown 1s ease-out;
        }
        
        @keyframes slideDown {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .hero h1 {
            font-size: 4em;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea, #764ba2, #f093fb);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .hero p {
            font-size: 1.3em;
            color: #666;
            margin-bottom: 40px;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .cta-buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 18px 35px;
            border: none;
            border-radius: 15px;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 15px 35px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6c757d, #495057);
            box-shadow: 0 10px 25px rgba(108, 117, 125, 0.3);
        }
        
        .btn-secondary:hover {
            box-shadow: 0 15px 35px rgba(108, 117, 125, 0.4);
        }
        
        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s ease;
            animation: slideUp 0.8s ease-out;
            position: relative;
            overflow: hidden;
        }
        
        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.05), rgba(118, 75, 162, 0.05));
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .feature-card:hover::before {
            opacity: 1;
        }
        
        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 30px 60px rgba(0,0,0,0.15);
        }
        
        @keyframes slideUp {
            from { transform: translateY(50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .feature-icon {
            font-size: 3em;
            margin-bottom: 20px;
            display: block;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }
        
        .feature-card h3 {
            font-size: 1.5em;
            font-weight: 700;
            color: #333;
            margin-bottom: 15px;
            position: relative;
            z-index: 1;
        }
        
        .feature-card p {
            color: #666;
            line-height: 1.6;
            position: relative;
            z-index: 1;
        }
        
        .demo-section {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: slideUp 0.8s ease-out;
        }
        
        .demo-section h2 {
            text-align: center;
            font-size: 2.5em;
            font-weight: 800;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 30px;
        }
        
        .demo-steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        .demo-step {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(102, 126, 234, 0.2);
            transition: all 0.3s ease;
        }
        
        .demo-step:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.2);
        }
        
        .demo-step-number {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.2em;
            margin: 0 auto 15px;
        }
        
        .demo-step h4 {
            color: #333;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .demo-step p {
            color: #666;
            font-size: 0.9em;
        }
        
        .team-section {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: slideUp 0.8s ease-out;
        }
        
        .team-section h2 {
            text-align: center;
            font-size: 2.5em;
            font-weight: 800;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 30px;
        }
        
        .team-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .team-member {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(102, 126, 234, 0.2);
            transition: all 0.3s ease;
        }
        
        .team-member:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(102, 126, 234, 0.2);
        }
        
        .team-member h4 {
            color: #333;
            margin-bottom: 10px;
            font-weight: 600;
        }
        
        .team-member p {
            color: #667eea;
            font-weight: 500;
            font-size: 0.9em;
        }
        
        .footer {
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: slideUp 0.8s ease-out;
        }
        
        .footer h3 {
            font-size: 2em;
            font-weight: 800;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
        }
        
        .footer p {
            color: #666;
            font-size: 1.1em;
            margin-bottom: 30px;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2.5em;
            }
            
            .hero p {
                font-size: 1.1em;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
                max-width: 300px;
            }
            
            .features-grid {
                grid-template-columns: 1fr;
            }
            
            .demo-steps {
                grid-template-columns: 1fr;
            }
            
            .team-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
        }
    </style>
</head>
<body>
    <!-- Animated Background Particles -->
    <div class="particles" id="particles"></div>
    
    <div class="container">
        <!-- Hero Section -->
        <div class="hero">
            <h1>🔒 Secure File Share</h1>
            <p>Enterprise-grade file sharing with military-level encryption, digital watermarking, and comprehensive security monitoring.</p>
            <div class="cta-buttons">
                <a href="index.php" class="btn">🚀 Try Demo</a>
                <a href="security_tests.php" class="btn btn-secondary">🧪 Security Tests</a>
            </div>
        </div>
        
        <!-- Features Grid -->
        <div class="features-grid">
            <div class="feature-card">
                <span class="feature-icon">🔐</span>
                <h3>AES-256 Encryption</h3>
                <p>Military-grade encryption ensures your files are protected with the same security standards used by governments and financial institutions.</p>
            </div>
            
            <div class="feature-card">
                <span class="feature-icon">🎯</span>
                <h3>Digital Watermarking</h3>
                <p>Invisible fingerprints embedded in every file allow you to track and identify the source of any unauthorized data leaks.</p>
            </div>
            
            <div class="feature-card">
                <span class="feature-icon">🛡️</span>
                <h3>Real-time Monitoring</h3>
                <p>Comprehensive audit logging and threat detection provide complete visibility into all file access and sharing activities.</p>
            </div>
            
            <div class="feature-card">
                <span class="feature-icon">🔑</span>
                <h3>2FA Authentication</h3>
                <p>Two-factor authentication with JWT tokens and TOTP ensures only authorized users can access your secure file sharing system.</p>
            </div>
            
            <div class="feature-card">
                <span class="feature-icon">👥</span>
                <h3>Role-Based Access</h3>
                <p>Granular permission system with Admin, User, and Viewer roles ensures proper access control for different organizational needs.</p>
            </div>
            
            <div class="feature-card">
                <span class="feature-icon">⏰</span>
                <h3>Auto Expiry</h3>
                <p>Files automatically expire after 24 hours, ensuring sensitive data doesn't remain accessible indefinitely and reducing security risks.</p>
            </div>
        </div>
        
        <!-- Demo Section -->
        <div class="demo-section">
            <h2>🚀 How It Works</h2>
            <div class="demo-steps">
                <div class="demo-step">
                    <div class="demo-step-number">1</div>
                    <h4>Login Securely</h4>
                    <p>Use demo accounts to experience different user roles and permissions</p>
                </div>
                <div class="demo-step">
                    <div class="demo-step-number">2</div>
                    <h4>Upload Files</h4>
                    <p>Files are automatically encrypted with AES-256 before storage</p>
                </div>
                <div class="demo-step">
                    <div class="demo-step-number">3</div>
                    <h4>Share Securely</h4>
                    <p>Share files with expiration dates and role-based permissions</p>
                </div>
                <div class="demo-step">
                    <div class="demo-step-number">4</div>
                    <h4>Monitor Activity</h4>
                    <p>Track all file access and detect suspicious activities</p>
                </div>
            </div>
        </div>
        
        <!-- Team Section -->
        <div class="team-section">
            <h2>👥 Development Team</h2>
            <div class="team-grid">
                <div class="team-member">
                    <h4>Mohamed Loai</h4>
                    <p>Backend Security Engineer</p>
                </div>
                <div class="team-member">
                    <h4>Khaled Sharaf</h4>
                    <p>Database Integration</p>
                </div>
                <div class="team-member">
                    <h4>Zayed Mohamed</h4>
                    <p>Frontend Developer</p>
                </div>
                <div class="team-member">
                    <h4>Youssef Mohamed</h4>
                    <p>UX/UI Designer</p>
                </div>
                <div class="team-member">
                    <h4>Mohamed Jamal</h4>
                    <p>Security Analyst</p>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <h3>Ready to Experience Secure File Sharing?</h3>
            <p>Try our demo with real encryption, authentication, and file management features.</p>
            <div class="cta-buttons">
                <a href="index.php" class="btn">🔒 Start Demo</a>
                <a href="security_tests.php" class="btn btn-secondary">🧪 View Tests</a>
            </div>
        </div>
    </div>
    
    <script>
        // Create animated background particles
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            const particleCount = 60;
            
            for (let i = 0; i < particleCount; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                
                // Random size between 2px and 8px
                const size = Math.random() * 6 + 2;
                particle.style.width = size + 'px';
                particle.style.height = size + 'px';
                
                // Random position
                particle.style.left = Math.random() * 100 + '%';
                particle.style.top = Math.random() * 100 + '%';
                
                // Random animation delay
                particle.style.animationDelay = Math.random() * 6 + 's';
                particle.style.animationDuration = (Math.random() * 4 + 4) + 's';
                
                particlesContainer.appendChild(particle);
            }
        }
        
        // Initialize particles on page load
        document.addEventListener('DOMContentLoaded', createParticles);
        
        // Add smooth scrolling for better UX
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>
</html>








from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
import sqlite3
import os
import jwt
import hashlib
from datetime import datetime
import subprocess
import json

app = Flask(__name__)
app.secret_key = "insecure_secret_key_123"
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB


# Database helper function - USE THIS EVERYWHERE
def get_db_connection():
    """Get database connection with correct path"""
    db_path = 'database.db'  # Simple path in current directory
    return sqlite3.connect(db_path)


# Initialize database on startup
def init_database():
    conn = get_db_connection()  # Use the helper function
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            public INTEGER DEFAULT 1
        )
    ''')
    
    # Insert default users if not exists
    users = [
        ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@vulnlab.com', 1),
        ('alice', hashlib.md5('password123'.encode()).hexdigest(), 'alice@example.com', 0),
        ('bob', hashlib.md5('bobpassword'.encode()).hexdigest(), 'bob@example.com', 0)
    ]
    
    for user in users:
        try:
            cursor.execute("INSERT OR IGNORE INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)", user)
        except Exception as e:
            print(f"Error inserting user: {e}")
    
    # Insert sample posts
    posts = [
        (1, 'Welcome to Vulnerable Lab', 'This is a intentionally vulnerable application for learning security testing.', 1),
        (2, 'User Alice Post', 'Hello, this is Alice posting here!', 1),
        (3, 'Private Post by Bob', 'This should be private but might be accessible.', 0),
        (1, 'Admin Secret Post', 'Important admin information here.', 0)
    ]
    
    for post in posts:
        try:
            cursor.execute("INSERT OR IGNORE INTO posts (user_id, title, content, public) VALUES (?, ?, ?, ?)", post)
        except Exception as e:
            print(f"Error inserting post: {e}")
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

# ==================== VULNERABLE ROUTES ====================

# VULNERABILITY 1: SQL Injection (A03:2021-Injection)
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    conn = get_db_connection()  # Fixed: Use helper function
    cursor = conn.cursor()
    
    # ⚠️ VULNERABLE: Direct string concatenation - SQL Injection
    sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
    print(f"Executing SQL: {sql}")  # Debug output
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    
    return render_template('search.html', results=results, query=query)

# VULNERABILITY 2: Cross-Site Scripting (A03:2021-Injection)
@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form.get('comment', '')
    # ⚠️ VULNERABLE: No input sanitization - Reflected XSS
    return f"""
    <html>
    <head><title>Comment Added</title></head>
    <body>
        <h1>Comment Added</h1>
        <p>Your comment: {comment}</p>
        <a href='/'>Go back to Home</a>
    </body>
    </html>
    """

# VULNERABILITY 3: Broken Authentication (A07:2021-Identification and Authentication Failures)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # ⚠️ VULNERABLE: Weak MD5 hashing + SQL injection
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db_connection()  # Fixed: Use helper function
        cursor = conn.cursor()
        # ⚠️ VULNERABLE: SQL Injection in login
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"
        print(f"Login SQL: {sql}")  # Debug output
        cursor.execute(sql)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # ⚠️ VULNERABLE: Insecure session handling
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[4]
            
            # ⚠️ VULNERABLE: JWT with weak algorithm
            token = jwt.encode({
                'user_id': user[0],
                'username': user[1],
                'admin': user[4]
            }, app.secret_key, algorithm='HS256')
            
            response = make_response(redirect(url_for('profile')))
            response.set_cookie('auth_token', token, httponly=False)  # ⚠️ Not HttpOnly
            return response
    
    return render_template('login.html')

# VULNERABILITY 4: Insecure Direct Object References (A01:2021-Broken Access Control)
@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    # ⚠️ VULNERABLE: No authorization check - IDOR
    conn = get_db_connection()  # Fixed: Use helper function
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return render_template('profile.html', 
                             user_id=user[0],
                             username=user[1], 
                             email=user[2],
                             is_admin=user[3])
    return "User not found"

# VULNERABILITY 5: Security Misconfiguration (A05:2021-Security Misconfiguration)
@app.route('/admin')
def admin_panel():
    # ⚠️ VULNERABLE: Hardcoded admin token
    admin_token = request.args.get('token', '')
    if admin_token == 'supersecrettoken123':
        conn = get_db_connection()  # Fixed: Use helper function
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        conn.close()
        return render_template('admin.html', users=users)
    return "Access denied: Invalid or missing admin token"

# VULNERABILITY 6: Command Injection (Additional)
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '127.0.0.1')
    # ⚠️ VULNERABLE: Direct command execution
    try:
        result = subprocess.check_output(f"ping -c 2 {host}", shell=True, text=True, stderr=subprocess.STDOUT)
        return f"""
        <html>
        <head><title>Ping Results</title></head>
        <body>
            <h1>Ping Results for {host}</h1>
            <pre>{result}</pre>
            <a href='/'>Go back</a>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY 7: Unrestricted File Upload (A03:2021-Injection)
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # ⚠️ VULNERABLE: No file type validation
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return f"""
            <html>
            <head><title>Upload Successful</title></head>
            <body>
                <h1>File Uploaded Successfully!</h1>
                <p>Filename: {filename}</p>
                <p>Saved to: {filepath}</p>
                <a href='/upload'>Upload another file</a> | 
                <a href='/'>Home</a>
            </body>
            </html>
            """
    return render_template('upload.html')

# ==================== REGULAR ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/profile')
def profile():
    if 'username' in session:
        conn = get_db_connection()  # Fixed: Use helper function
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id=?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return render_template('profile.html', 
                                 user_id=user[0],
                                 username=user[1], 
                                 email=user[2],
                                 is_admin=user[3])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    response = make_response(redirect(url_for('index')))
    response.set_cookie('auth_token', '', expires=0)
    return response

@app.route('/debug')
def debug_info():
    # ⚠️ VULNERABLE: Debug information exposure
    info = {
        "session": dict(session),
        "cookies": dict(request.cookies),
        "headers": dict(request.headers),
        "app_config": {
            "debug": app.debug,
            "secret_key": app.secret_key[:10] + "..."
        }
    }
    return jsonify(info)

# ==================== MAIN ====================

if __name__ == '__main__':
    # Create necessary directories
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    
    # Initialize database (always do this, not just if file doesn't exist)
    print("🔧 Initializing database...")
    init_database()
    
    print("=" * 50)
    print("VULNERABLE WEB APPLICATION LAB")
    print("=" * 50)
    print("Available at: http://localhost:5000")
    print("Test Credentials:")
    print("  - admin / admin123")
    print("  - alice / password123")
    print("  - bob / bobpassword")
    print("=" * 50)
    print("SQL Injection test: http://localhost:5000/search?q=test")
    print("SQL Injection payload: http://localhost:5000/search?q=' OR '1'='1")
    print("=" * 50)
    
    # ⚠️ VULNERABLE: Running with debug mode enabled
    app.run(host='0.0.0.0', port=5000, debug=True)

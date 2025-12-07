from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Session ke liye secret key

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('project.db')
    conn.row_factory = sqlite3.Row
    return conn

# Database setup - Users table with password field
def init_auth_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Auth ke liye Users table me password column add karna
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS AuthUsers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

# Initialize database on startup
init_auth_db()

# ==========================================
# REGISTRATION ENDPOINT
# ==========================================
@app.route('/register', methods=['POST'])
def register():
    """
    Naye user ko register karta hai.
    JSON format: {"username": "ali", "password": "secret123", "email": "ali@example.com"}
    """
    try:
        data = request.get_json()

        if not data or not data.get('username') or not data.get('password'):
            return jsonify({"error": "Username aur password required hain"}), 400

        username = data['username']
        password = data['password']
        email = data.get('email', '')

        # Password hash karna (security ke liye)
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # User ko database me save karna
        cursor.execute(
            'INSERT INTO AuthUsers (username, password_hash, email) VALUES (?, ?, ?)',
            (username, password_hash, email)
        )
        conn.commit()
        conn.close()

        return jsonify({
            "message": "User successfully registered!",
            "username": username
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500


# ==========================================
# LOGIN ENDPOINT
# ==========================================
@app.route('/login', methods=['POST'])
def login():
    """
    User ko login karta hai.
    JSON format: {"username": "ali", "password": "secret123"}
    """
    try:
        data = request.get_json()

        if not data or not data.get('username') or not data.get('password'):
            return jsonify({"error": "Username aur password required hain"}), 400

        username = data['username']
        password = data['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Database se user ko dhoondhna
        cursor.execute('SELECT * FROM AuthUsers WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        # User exists aur password sahi hai?
        if user and check_password_hash(user['password_hash'], password):
            # Session me user ko save karna
            session['user_id'] = user['id']
            session['username'] = user['username']

            return jsonify({
                "message": "Login successful!",
                "username": username
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401

    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500


# ==========================================
# LOGOUT ENDPOINT
# ==========================================
@app.route('/logout', methods=['POST'])
def logout():
    """
    User ko logout karta hai (session clear karta hai).
    """
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200


# ==========================================
# PROTECTED ROUTE EXAMPLE
# ==========================================
@app.route('/profile', methods=['GET'])
def profile():
    """
    Protected route - sirf logged in users access kar sakte hain.
    """
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized. Please login first."}), 401

    return jsonify({
        "message": "Welcome to your profile!",
        "username": session.get('username'),
        "user_id": session.get('user_id')
    }), 200


# ==========================================
# HEALTH CHECK
# ==========================================
@app.route('/health', methods=['GET'])
def health():
    """API health check"""
    return jsonify({"status": "ok", "message": "Auth API is running"}), 200


if __name__ == '__main__':
    print("Flask Authentication Server starting...")
    print("Available endpoints:")
    print("  POST /register - New user registration")
    print("  POST /login    - User login")
    print("  POST /logout   - User logout")
    print("  GET  /profile  - Protected route (requires login)")
    print("  GET  /health   - Health check")
    app.run(debug=True, host='0.0.0.0', port=5000)

from mcp.server.fastmcp import FastMCP
import subprocess
import sqlite3
import os
import smtplib
from email.mime.text import MIMEText
import paramiko # Server Deployment (SSH) ke liye

# Server ka naam
mcp = FastMCP("DevOpsSuperBot")

# ==========================================
# SKILL 1: GITHUB AUTOMATION (Create -> Push)
# ==========================================
@mcp.tool()
def github_manager(action: str, repo_name: str = "", commit_message: str = "Auto update by Claude"):
    """
    GitHub manage karne k liye full suite.
    
    Args:
        action: 'create_repo', 'push', 'status', 'clone'
        repo_name: Repo ka naam (create/clone k liye)
        commit_message: Commit k liye message
    """
    try:
        if action == "create_repo":
            # GitHub CLI (gh) use karega naya repo banane k liye
            # Requirement: 'gh auth login' pehle se kiya ho
            cmd = ["gh", "repo", "create", repo_name, "--public", "--source=.", "--remote=origin"]
            subprocess.run(cmd, check=True)
            subprocess.run(["git", "push", "-u", "origin", "main"], check=True)
            return f"Repo '{repo_name}' created and code pushed!"

        elif action == "push":
            # Existing code ko push karna
            subprocess.run(["git", "add", "."], check=True)
            subprocess.run(["git", "commit", "-m", commit_message], check=True)
            subprocess.run(["git", "push"], check=True)
            return "Code successfully committed and pushed to GitHub."

        elif action == "status":
            result = subprocess.run(["git", "status"], capture_output=True, text=True)
            return result.stdout

        return "Unknown action. Use: create_repo, push, or status."
    
    except subprocess.CalledProcessError as e:
        return f"Git Error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


# ==========================================
# SKILL 2: DATABASE OPERATIONS
# ==========================================
@mcp.tool()
def database_ops(query: str, db_path: str = "project.db"):
    """
    Database par SQL query run karta hai.
    Create table, Insert data, or Select data.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        conn.commit()
        
        # Agar SELECT query hai to data wapis bhejo
        if query.strip().upper().startswith("SELECT"):
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            return f"Columns: {columns}\nData: {rows}"
            
        return "Query executed successfully."
    except Exception as e:
        return f"DB Error: {str(e)}"
    finally:
        conn.close()


# ==========================================
# SKILL 3: AUTHENTICATION BOILERPLATE
# ==========================================
@mcp.tool()
def generate_auth_code(framework: str):
    """
    Projects me Authentication add karne k liye code generate karta hai.
    Args: framework ('flask' or 'fastapi')
    """
    if framework.lower() == "flask":
        code = """
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
users_db = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    users_db[data['username']] = generate_password_hash(data['password'])
    return jsonify({"message": "User registered"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_pw = users_db.get(data['username'])
    if user_pw and check_password_hash(user_pw, data['password']):
        return jsonify({"message": "Login Successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401
"""
        filename = "auth_flask.py"
    
    elif framework.lower() == "fastapi":
        code = """
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(user: User):
    if user.username == "admin" and user.password == "secret":
        return {"token": "fake-jwt-token"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")
"""
        filename = "auth_fastapi.py"
    else:
        return "Sirf 'flask' ya 'fastapi' framework supported hain."

    with open(filename, "w") as f:
        f.write(code)
    return f"Authentication code saved in {filename}"


# ==========================================
# SKILL 4: SERVER DEPLOYMENT (SSH)
# ==========================================
@mcp.tool()
def deploy_via_ssh(hostname: str, username: str, key_path: str, command: str):
    """
    Real Server Deployment via SSH.
    Server par connect karke command run karta hai (e.g., 'git pull').
    """
    try:
        # SSH Client setup
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Key file load karna
        k = paramiko.RSAKey.from_private_key_file(key_path)
        
        # Connect
        client.connect(hostname=hostname, username=username, pkey=k)
        
        # Command run karna
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        client.close()
        
        if error:
            return f"Deployment Warning/Error: {error}"
        return f"Deployment Output: {output}"
        
    except Exception as e:
        return f"SSH Connection Failed: {str(e)}"


# ==========================================
# SKILL 5: EMAIL SENDING
# ==========================================
@mcp.tool()
def send_email(to_email: str, subject: str, body: str):
    """
    Gmail ya SMTP k zariye email send karta hai.
    Note: App password use karna behtar hai.
    """
    # Security: Hardcoding password is bad. Environment variable use karein.
    sender_email = os.getenv("MY_EMAIL_USER") # e.g., 'you@gmail.com'
    sender_password = os.getenv("MY_EMAIL_PASS") # App Password
    
    if not sender_email or not sender_password:
        return "Error: Please set MY_EMAIL_USER and MY_EMAIL_PASS environment variables."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = to_email

    try:
        # Gmail SMTP Settings
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender_email, sender_password)
            smtp_server.sendmail(sender_email, to_email, msg.as_string())
        return f"Email sent successfully to {to_email}"
    except Exception as e:
        return f"Email Failed: {str(e)}"


# ==========================================
# SKILL 6: LOG ANALYSIS (RAG - Context 7)
# ==========================================
@mcp.tool()
def analyze_logs(file_path: str, keyword: str = "ERROR"):
    """
    Log file ko parhta hai aur specific errors dhoondta hai.
    """
    if not os.path.exists(file_path):
        return "File not found."
    
    found_lines = []
    try:
        with open(file_path, "r") as f:
            # Last 1000 lines parhna performance k liye
            lines = f.readlines()[-1000:]
            
            for line in lines:
                if keyword in line:
                    found_lines.append(line.strip())
        
        if not found_lines:
            return f"No logs found containing '{keyword}'."
            
        return "\n".join(found_lines[-20:]) # Sirf aakhri 20 errors wapis karo
    except Exception as e:
        return f"Error reading logs: {str(e)}"

# Server start
if __name__ == "__main__":
    mcp.run()

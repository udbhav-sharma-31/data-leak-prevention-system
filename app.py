from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json, os, base64
from datetime import datetime

# OpenAI
from dotenv import load_dotenv
from openai import OpenAI
import os

# Ensure instance directory exists (Render fix)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")

os.makedirs(INSTANCE_DIR, exist_ok=True)
load_dotenv()

# ---------------- FLASK APP INIT ----------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret_key")

# ---------------- DATABASE CONFIG ----------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(INSTANCE_DIR, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ---------------- SINGLE GLOBAL SQLALCHEMY INSTANCE ----------------
db = SQLAlchemy()     # ✅ Create ONE db instance
db.init_app(app)      # ✅ Bind it to the Flask app BEFORE models import

# ---------------- IMPORT MODELS AFTER db IS ATTACHED ----------------
from models import User, ScanResult, UploadedFile, EncryptionKey, LeakAlert, ActivityLog
from helpers.scanner import scan_file
from helpers.encryption import (
    encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa, generate_rsa_keys
)
from cloud_scanner.rules import detect_sensitive_data

# --- AUTO CREATE DB FOR RENDER FREE TIER ---
with app.app_context():
    db.create_all()
    print("DB created at startup.")


# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- JINJA FILTER ----------------
@app.template_filter('b64encode')
def b64encode_filter(data):
    if isinstance(data, (bytes, bytearray)):
        return base64.b64encode(data).decode('utf-8')
    return data

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password!", "danger")

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# ---------- FILE SCAN ----------
ALLOWED_EXTENSIONS = {'.txt', '.py', '.env', '.json', '.csv', '.yaml', '.yml', '.md'}

def allowed_file(filename):
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS

@app.route('/file_scan', methods=['GET', 'POST'])
@login_required
def file_scan():
    results = None
    message = None

    if request.method == 'POST':
        uploaded_file = request.files.get('file')

        if not uploaded_file:
            message = ("danger", "No file selected")
        elif not allowed_file(uploaded_file.filename):
            message = ("danger", "File type not allowed")
        else:
            content = uploaded_file.read().decode('utf-8', errors='ignore')
            results = scan_file(content)

            found_count = sum(x.get('count', 0) for x in results)
            findings_json = json.dumps(results)

            scan = ScanResult(
                user_id=current_user.id,
                filename=uploaded_file.filename,
                findings=findings_json,
                found_count=found_count,
                created_at=datetime.utcnow()
            )
            db.session.add(scan)
            db.session.commit()

            if found_count == 0:
                message = ("success", "No sensitive data found")
            else:
                message = ("warning", f"{found_count} sensitive items found")

    history_raw = ScanResult.query.filter_by(user_id=current_user.id).order_by(
        ScanResult.created_at.desc()
    ).limit(10).all()

    history = []
    for entry in history_raw:
        try:
            parsed = json.loads(entry.findings)
        except:
            parsed = []
        history.append({
            "filename": entry.filename,
            "created_at": entry.created_at,
            "found_count": entry.found_count,
            "findings": parsed
        })

    return render_template('file_scan.html', results=results, message=message, history=history)

# ---------- ENCRYPT ----------
@app.route('/encrypt_file', methods=['GET', 'POST'])
@login_required
def encrypt_file():
    download_filename = None
    key_filename = None
    key_data = None

    if request.method == 'POST':
        file = request.files.get('file')
        algo = request.form.get('algorithm')

        if not file:
            flash("No file selected", "danger")
            return redirect(url_for('encrypt_file'))

        file_bytes = file.read()
        filename = file.filename

        if algo == "AES":
            encrypted, key = encrypt_aes(file_bytes)
            key_data = key
            key_filename = "aes_key.bin"
        else:
            private_key, public_key = generate_rsa_keys()
            encrypted = encrypt_rsa(file_bytes, public_key)
            key_data = private_key
            key_filename = "rsa_private.pem"

        output_filename = f"encrypted_{filename}"
        output_path = os.path.join(app.static_folder, output_filename)
        with open(output_path, "wb") as f:
            f.write(encrypted)

        download_filename = output_filename
        flash("File encrypted!", "success")

    return render_template('encrypt_file.html',
                           download_filename=download_filename,
                           key_data=key_data,
                           key_filename=key_filename)

# ---------- DECRYPT ----------
@app.route('/decrypt_file', methods=['GET', 'POST'])
@login_required
def decrypt_file():
    decrypted_filename = None

    if request.method == 'POST':
        file = request.files.get('file')
        key_file = request.files.get('key')
        algo = request.form.get('algorithm')

        if not file or not key_file:
            flash("Upload both encrypted file and key!", "danger")
            return redirect(url_for('decrypt_file'))

        file_bytes = file.read()
        key_bytes = key_file.read()

        if algo == "AES":
            decrypted = decrypt_aes(file_bytes, key_bytes)
        else:
            decrypted = decrypt_rsa(file_bytes, key_bytes)

        output_filename = f"decrypted_{file.filename}"
        output_path = os.path.join(app.static_folder, output_filename)
        with open(output_path, "wb") as f:
            f.write(decrypted)

        decrypted_filename = output_filename
        flash("File decrypted!", "success")

    return render_template('decrypt_file.html', decrypted_filename=decrypted_filename)

# ---------- LOGOUT ----------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out!", "info")
    return redirect(url_for('login'))

# ---------- AI ASSISTANT ----------
@app.route('/assistant')
@login_required
def assistant():
    return render_template('assistant.html')

@app.route('/ask_ai', methods=['POST'])
@login_required
def ask_ai():
    user_message = request.json.get("message")

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a cybersecurity assistant."},
            {"role": "user", "content": user_message},
        ]
    )
    
    return {"reply": response.choices[0].message.content}

# ---------- LOCAL RUN ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

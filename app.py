from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from helpers.scanner import scan_file  
import json
import os
from datetime import datetime
from helpers.scanner import scan_file
from models import db, User, ScanResult, LeakAlert
from flask import send_file
from helpers.encryption import encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa, generate_rsa_keys
from cloud_scanner.rules import detect_sensitive_data
from flask import redirect, session
import os
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from cloud_scanner.gdrive_scan import get_drive_service, scan_drive_files


# ✅ keep only this import once
from dotenv import load_dotenv
import openai
import os
from openai import OpenAI
with app.app_context():
    try:
        db.create_all()
        print("Tables created successfully on startup.")
    except Exception as e:
        print("DB creation error:", e)
load_dotenv()
client = OpenAI()
openai.api_key = os.getenv("OPENAI_API_KEY")
# ✅ Flask app initialization
app = Flask(__name__)
with app.app_context():
    from models import db
    db.create_all()
app.secret_key = 'supersecretkey'

# ---- Register b64encode Jinja Filter ----
import base64

@app.template_filter('b64encode')
def b64encode_filter(data):
    """Base64 encode binary data for safe download links."""
    if isinstance(data, (bytes, bytearray)):
        return base64.b64encode(data).decode('utf-8')
    return data


# ✅ Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

# ✅ Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    
    return User.query.get(int(user_id))

# ✅ ROUTES

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
        if not uploaded_file or uploaded_file.filename == '':
            message = ("danger", "No file selected.")
        elif not allowed_file(uploaded_file.filename):
            message = ("danger", f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")
        else:
            # read file safely
            content = uploaded_file.read().decode('utf-8', errors='ignore')
            results = scan_file(content)  # list of dicts from your scanner

            # summarize findings
            found_count = sum(item.get('count', 0) for item in results) if results else 0
            findings_text = json.dumps(results, ensure_ascii=False)

            # Save to DB
            scan = ScanResult(
                user_id=current_user.id,
                filename=uploaded_file.filename,
                findings=findings_text,
                found_count=found_count,
                created_at=datetime.utcnow()
            )
            db.session.add(scan)
            db.session.commit()

            if found_count == 0:
                message = ("success", "Scan completed — no sensitive data found.")
            else:
                message = ("warning", f"Scan completed — {found_count} potential sensitive item(s) found.")

    # Load recent scans for current user (last 10)
    history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.created_at.desc()).limit(10).all()
    # convert findings JSON back to structure for display
    history_display = []
    for h in history:
        try:
            parsed = json.loads(h.findings) if h.findings else []
        except Exception:
            parsed = []
        history_display.append({
            'id': h.id,
            'filename': h.filename,
            'found_count': h.found_count,
            'created_at': h.created_at,
            'findings': parsed
        })

    return render_template('file_scan.html', results=results, message=message, history=history_display)

@app.route('/encrypt_file', methods=['GET', 'POST'])
@login_required
def encrypt_file():
    download_filename = None
    key_data = None
    key_filename = None
    algorithm_used = None

    if request.method == 'POST':
        file = request.files.get('file')
        algo = request.form.get('algorithm')

        if not file:
            flash("No file selected!", "danger")
            return redirect(url_for('encrypt_file'))

        file_bytes = file.read()
        filename = file.filename

        if algo == 'AES':
            encrypted_data, key = encrypt_aes(file_bytes)
            key_data = key
            key_filename = "aes_key.bin"
            algorithm_used = "AES"

        elif algo == 'RSA':
            priv_key, pub_key = generate_rsa_keys()
            encrypted_data = encrypt_rsa(file_bytes, pub_key)
            key_data = priv_key
            key_filename = "rsa_private.pem"
            algorithm_used = "RSA"

        else:
            flash("Invalid encryption option selected!", "danger")
            return redirect(url_for('encrypt_file'))

        # ✅ Save encrypted file
        output_filename = f"encrypted_{filename}"
        output_path = os.path.join(app.static_folder, output_filename)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)

        download_filename = output_filename
        flash(f"{algorithm_used} encryption successful! Download your encrypted file and key below.", "success")

    # ✅ Always return cleanly aligned at base indentation level
    return render_template(
        'encrypt_file.html',
        download_filename=download_filename,
        key_data=key_data,
        key_filename=key_filename
    )


@app.route('/decrypt_file', methods=['GET', 'POST'])
@login_required
def decrypt_file():
    decrypted_filename = None
    error_message = None

    if request.method == 'POST':
        file = request.files.get('file')
        key_file = request.files.get('key')
        algo = request.form.get('algorithm')

        if not file or not key_file:
            flash("Please upload both encrypted file and key!", "danger")
            return redirect(url_for('decrypt_file'))

        file_bytes = file.read()
        key_bytes = key_file.read()

        try:
            if algo == 'AES':
                decrypted_data = decrypt_aes(file_bytes, key_bytes)
            elif algo == 'RSA':
                decrypted_data = decrypt_rsa(file_bytes, key_bytes)
            else:
                flash("Invalid decryption option selected!", "danger")
                return redirect(url_for('decrypt_file'))

            # Save decrypted output
            output_filename = f"decrypted_{file.filename}"
            output_path = os.path.join(app.static_folder, output_filename)
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            decrypted_filename = output_filename
            flash(f"{algo} decryption successful! Download your decrypted file below.", "success")

        except Exception as e:
            error_message = f"Decryption failed: {str(e)}"
            flash(error_message, "danger")


    return render_template('decrypt_file.html', decrypted_filename=decrypted_filename)

@app.route("/cloud")
@login_required
def cloud_dashboard():
    gdrive_results = session.pop("gdrive_results", None)

    print("CLOUD PAGE RESULTS:", gdrive_results)  # 🔥 DEBUG

    return render_template(
        "cloud_scan.html",
        gdrive_results=gdrive_results
    )





@app.route('/cloud/scan', methods=['POST'])
@login_required
def cloud_scan_file():
    from cloud_scanner.rules import detect_sensitive_data

    sample_text = """
    Aadhaar Number: 1234 5678 9123
    PAN: ABCDE1234F
    Email: test@example.com
    password = "secret123"
    """

    findings = detect_sensitive_data(sample_text)
    total_found = sum(findings.values())

    scan = ScanResult(
        user_id=current_user.id,
        filename="Cloud_File_Demo.txt",
        findings=json.dumps(findings),
        found_count=total_found,
        created_at=datetime.utcnow()
    )
    db.session.add(scan)
    db.session.commit()

    if total_found > 0:
        alert = LeakAlert(
            scan_id=scan.id,
            severity="HIGH",
            message="Sensitive data detected in cloud file"
        )
        db.session.add(alert)
        db.session.commit()

    # 🔥 Render SAME page with results
    return render_template(
        "cloud_scan.html",
        findings=findings,
        total_found=total_found
    )
@app.route("/gdrive/connect", methods=["GET", "POST"])
@login_required
def gdrive_connect():
    session.pop("state", None)
    session.pop("gdrive_results", None) 

    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=["https://www.googleapis.com/auth/drive.readonly"],
        redirect_uri="http://127.0.0.1:5000/gdrive/callback"
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",     # 🔥 REQUIRED
        prompt="consent",          # 🔥 REQUIRED (forces refresh_token)
        include_granted_scopes="true"
    )

    session["state"] = state
    return redirect(authorization_url)


@app.route("/gdrive/callback")
@login_required
def gdrive_callback():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=["https://www.googleapis.com/auth/drive.readonly"],
        state=session.get("state"),
        redirect_uri="http://127.0.0.1:5000/gdrive/callback"
    )

    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    service = build("drive", "v3", credentials=creds)

    from cloud_scanner.rules import detect_sensitive_data

    results = []

    response = service.files().list(
        pageSize=10,
        fields="files(id, name, mimeType)"
    ).execute()

    files = response.get("files", [])

    for f in files:
        mime = f["mimeType"]

        if mime not in [
            "text/plain",
            "application/vnd.google-apps.document"
        ]:
            continue

        if mime == "application/vnd.google-apps.document":
            content = service.files().export(
                fileId=f["id"],
                mimeType="text/plain"
            ).execute().decode("utf-8", errors="ignore")
        else:
            content = service.files().get_media(
                fileId=f["id"]
            ).execute().decode("utf-8", errors="ignore")

        findings = detect_sensitive_data(content)
        total = sum(findings.values())

        if total == 0:
            continue

        results.append({
            "filename": f["name"],
            "findings": findings,
            "total": total
        })

    # ✅ THESE LINES MUST BE INDENTED INSIDE THE FUNCTION
    session["gdrive_results"] = results
    print("GDRIVE RESULTS:", results)

    return redirect(url_for("cloud_dashboard"))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))


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
            {"role": "system", "content": "You are a cybersecurity assistant inside the Data Leak Prevention platform. Answer clearly, simply, and helpfully."},
            {"role": "user", "content": user_message}
        ]
    )

    reply = response.choices[0].message.content
    return {"reply": reply}

   

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

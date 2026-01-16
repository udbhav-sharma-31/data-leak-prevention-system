from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

from app import db

# ---------------- USER MODEL ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    scans = db.relationship('ScanResult', backref='user', lazy=True)
    files = db.relationship('UploadedFile', backref='user', lazy=True)
    activities = db.relationship('ActivityLog', backref='user', lazy=True)

# ---------------- FILE UPLOAD MODEL ----------------
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    original_filename = db.Column(db.String(260), nullable=False)
    encrypted_filename = db.Column(db.String(260), nullable=False)

    encryption_type = db.Column(db.String(50))  # AES / RSA
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- SCAN RESULT MODEL ----------------
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    filename = db.Column(db.String(260), nullable=False)
    findings = db.Column(db.Text)  # JSON result
    found_count = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- ENCRYPTION KEY MODEL ----------------
class EncryptionKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'))
    key_type = db.Column(db.String(20))  # AES / RSA
    key_reference = db.Column(db.String(255))  # path or identifier

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- LEAK ALERT MODEL ----------------
class LeakAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))
    severity = db.Column(db.String(20))  # LOW / MEDIUM / HIGH
    message = db.Column(db.String(255))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- ACTIVITY LOG MODEL ----------------
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200))  # upload, scan, encrypt, decrypt
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

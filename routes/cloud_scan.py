from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from app.models import ScanResult, LeakAlert, db
from cloud_scanner.rules import detect_sensitive_data
import json
from flask import render_template

cloud_scan = Blueprint("cloud_scan", __name__)

@cloud_scan.route("/cloud", methods=["GET"])
@login_required
def cloud_dashboard():
    return render_template("cloud_scan.html")

@cloud_scan.route("/cloud/scan", methods=["GET"])
@login_required
def cloud_scan_file():
    """
    Demo Cloud Scan Endpoint
    Later replace `sample_text` with real cloud file content
    """

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
        found_count=total_found
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

    return jsonify({
        "status": "success",
        "findings": findings,
        "total_detected": total_found
    })

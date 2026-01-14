from flask import Blueprint, redirect, session, url_for
from flask_login import login_required, current_user
from cloud_scanner.gdrive_auth import get_auth_flow, get_drive_service
from cloud_scanner.gdrive_scanner import GoogleDriveScanner
from app.models import ScanResult, LeakAlert, db
import json

gdrive = Blueprint("gdrive", __name__)

@gdrive.route("/gdrive/connect")
@login_required
def gdrive_connect():
    flow = get_auth_flow()
    auth_url, state = flow.authorization_url(prompt="consent")
    session["state"] = state
    return redirect(auth_url)

@gdrive.route("/gdrive/callback")
@login_required
def gdrive_callback():
    flow = get_auth_flow()
    flow.fetch_token(authorization_response=url_for("gdrive.gdrive_callback", _external=True))

    credentials = flow.credentials
    service = get_drive_service(credentials)

    scanner = GoogleDriveScanner(service)
    files = scanner.list_files()

    for file in files[:5]:  # limit scan
        content = scanner.read_file(file["id"])
        findings = scanner.scan_file(content)

        scan = ScanResult(
            user_id=current_user.id,
            filename=file["name"],
            findings=json.dumps(findings),
            found_count=sum(findings.values())
        )
        db.session.add(scan)
        db.session.commit()

        if scan.found_count > 0:
            alert = LeakAlert(
                scan_id=scan.id,
                severity="HIGH",
                message="Sensitive data detected in Google Drive file"
            )
            db.session.add(alert)
            db.session.commit()

    return "Google Drive Scan Completed Successfully"

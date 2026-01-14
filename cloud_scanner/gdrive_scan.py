from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from cloud_scanner.rules import detect_sensitive_data
import io

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

def get_drive_service(token):
    creds = Credentials.from_authorized_user_info(token, SCOPES)
    return build("drive", "v3", credentials=creds)

def scan_drive_files(service, max_files=5):
    results = []

    response = service.files().list(
        pageSize=max_files,
        fields="files(id, name, mimeType)"
    ).execute()

    files = response.get("files", [])

    for f in files:
        mime = f["mimeType"]

     # Allow Google Docs and text files
        if mime not in [
            "text/plain",
            "application/vnd.google-apps.document"
        ]:
            continue

        request = service.files().get_media(fileId=f["id"])
        content = request.execute().decode("utf-8", errors="ignore")

        findings = detect_sensitive_data(content)

        results.append({
            "filename": f["name"],
            "findings": findings,
            "total": sum(findings.values())
        })

    return results

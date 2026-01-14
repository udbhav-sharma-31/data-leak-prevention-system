from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

def get_auth_flow():
    return Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES,
        redirect_uri="http://127.0.0.1:5000/gdrive/callback"
    )

def get_drive_service(credentials):
    return build("drive", "v3", credentials=credentials)

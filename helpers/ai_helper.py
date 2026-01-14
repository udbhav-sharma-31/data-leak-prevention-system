import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = (
    "You are an AI helper inside a Data Leak Detection & Prevention web app. "
    "Guide users on scanning files, encryption/decryption, AWS S3 checks, and basic security hygiene. "
    "Be concise, step-by-step, and never ask for real secrets."
)

def ask_ai(message: str) -> str:
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": message.strip()}
            ],
            temperature=0.3,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        # Return a friendly message instead of crashing
        return f"Sorry, I couldn't answer right now ({type(e).__name__}). Please try again."

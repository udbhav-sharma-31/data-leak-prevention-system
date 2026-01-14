import re

def scan_file(file_content):
    results = []

    patterns = {
        "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Password-like String": r"(password\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*]{6,})",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Private Key": r"-----BEGIN PRIVATE KEY-----",
        "API Key": r"['\"]?([A-Za-z0-9_\-]{32,45})['\"]?",
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, file_content)
        if matches:
            results.append({"type": name, "count": len(matches), "examples": matches[:3]})
    
    return results

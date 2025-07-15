"""
task_manager.py
Simulates a microservice for task management with REST API calls, JWT authentication, and logging.
Includes test secrets for secret scanning tool evaluations.
All secrets are fake and used for testing/demo purposes only.
"""

import jwt
import logging
import requests
import os

# Logging setup
logging.basicConfig(level=logging.INFO)

# --- CONFIG SECTION (where secrets are often accidentally committed)

API_URL = "https://api.example.com/tasks"

# 1Password Secret Key (Fake)
ONEPASSWORD_SECRET = "A3-9XZ6KQ-7Y3VJQMWTCL-MK4LX-L1Z2C-GQ9JH"

# Prefect API Token (Fake)
PREFECT_API_TOKEN = "pnu_1234567890abcdef1234567890abcdef1234"

# GitLab session cookie (Fake)
SESSION_COOKIE = "_gitlab_session=4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"

# Slack Token (Fake)
SLACK_TOKEN = "xoxp-123456789012-123456789012-123456789012-abcdefghijklmnoPQRSTUVWXYZ"

# JWT Token (Fake)
JWT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSIsImlhdCI6MTUxNjIzOTAyMn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# Base64 JWT (Fake)
BASE64_JWT = (
    "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJbXRwWkNJNkltTnZiVENDQ2p3aWEzVWlPaUl5TXpFME9EZ3lPVEF3TXpZeE1pSXNJblI1Y0NJNkluUnlkV1VpT2lJeE5qRTFNRFl6T0RBd0lpd2lZWFZrSWpvaVlYUm9iMlJwWm1sbGNpNWpiMjB2SW4w"
)

# Fake Private Key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEArV8N9VqVVkVkdU8bGLiZ+j23BlP0aRGF3VGpV+Y2fXkQXjMu
qkwcOeN5yA2RNL5oF4v4N2vOiy9Ft5uUxR2TxH+ufwIDAQABAoIBABs87hXe3QVD
dF+T+MnoC1C0LBGZhyQyCvN3BQbE7O5UzPMPaWgbxCj+Q==
-----END RSA PRIVATE KEY-----"""

# --- CORE FUNCTIONALITY

def fetch_tasks(jwt_token):
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Slack-Token": SLACK_TOKEN,  # Intentionally left here
        "Cookie": SESSION_COOKIE
    }
    try:
        response = requests.get(API_URL, headers=headers)
        logging.info("Tasks fetched: %s", response.status_code)
    except Exception as e:
        logging.error("Error fetching tasks: %s", str(e))


def decode_jwt(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        logging.info("Decoded JWT: %s", decoded)
        return decoded
    except Exception as e:
        logging.warning("Failed to decode JWT: %s", str(e))
        return None


def main():
    logging.info("Starting Task Manager Microservice")

    # Step 1: Decode JWT
    decode_jwt(JWT_TOKEN)

    # Step 2: Fetch tasks
    fetch_tasks(JWT_TOKEN)

    # Step 3: Simulate key usage
    logging.debug("Using 1Password Key: %s", ONEPASSWORD_SECRET)
    logging.debug("Using Prefect Token: %s", PREFECT_API_TOKEN)

    # Step 4: Save private key to test storage
    with open("rsa_key.pem", "w") as f:
        f.write(PRIVATE_KEY)

    logging.info("Microservice execution complete.")


if __name__ == "__main__":
    main()

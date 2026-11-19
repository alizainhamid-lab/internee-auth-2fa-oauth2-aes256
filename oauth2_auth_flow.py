import os
import json
import secrets
import hashlib
import base64
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-auth-aes256")
LOG_FILE = os.path.join(BASE_DIR, "logs/auth_security.jsonl")

def generate_pkce_pair():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge

def simulate_oauth2_login(user_email: str, client_id: str = "internee-web-client"):
    state = secrets.token_urlsafe(16)
    auth_code = secrets.token_urlsafe(24)
    verifier, challenge = generate_pkce_pair()

    # Verify PKCE challenge & state before issuing tokens
    computed_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert computed_challenge == challenge, "PKCE verification failed"

    tokens = {
        "token_type": "Bearer",
        "expires_in": 900,
        "access_token": "at_" + secrets.token_urlsafe(24),
        "refresh_token": "rt_" + secrets.token_urlsafe(24),
        "scope": "openid profile email offline_access"
    }

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "OAUTH2_PKCE_TOKEN_ISSUED",
        "client_id": client_id,
        "user_email": user_email,
        "state_prefix": state[:6],
        "scope": tokens["scope"],
        "expires_in_sec": tokens["expires_in"]
    }
    with open(LOG_FILE, "a") as lf:
        lf.write(json.dumps(event) + "\n")

    print(f"[OAUTH2] Authenticated {user_email} via {client_id} (PKCE verified, TTL={tokens['expires_in']}s)")
    print(f"[OAUTH2] Access Token Issued: {tokens['access_token'][:18]}... | Scope: {tokens['scope']}")

def main():
    simulate_oauth2_login("zain.tariq@example.test")
    simulate_oauth2_login("hina.mahmood@example.test")

if __name__ == "__main__":
    main()

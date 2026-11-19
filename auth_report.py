import os
import json
from collections import Counter

BASE_DIR = os.path.expanduser("~/internee-auth-aes256")
LOG_FILE = os.path.join(BASE_DIR, "logs/auth_security.jsonl")
SUMMARY_OUT = os.path.join(BASE_DIR, "submission_summary.txt")

def main():
    events = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            events = [json.loads(line) for line in f if line.strip()]

    counts = Counter(e.get("event", "UNKNOWN") for e in events)
    summary = "\n".join([
        "Internee.pk Auth Hardening & AES-256 Task - Summary",
        f"AES-256 Vault Encryptions: {counts.get('AES256_VAULT_ENCRYPTED', 0)}",
        f"TOTP 2FA Verifications: {counts.get('TOTP_2FA_VERIFIED', 0)}",
        f"OAuth 2.0 PKCE Token Issuances: {counts.get('OAUTH2_PKCE_TOKEN_ISSUED', 0)}",
        "Controls Configured: AES-256 Encrypt-then-MAC Vault, Google Authenticator TOTP (RFC 6238), OAuth 2.0 + PKCE Token Flow."
    ]) + "\n"

    with open(SUMMARY_OUT, "w") as out:
        out.write(summary)

    print(summary)
    print(f"[+] Saved summary to: {SUMMARY_OUT}")

if __name__ == "__main__":
    main()

import os
import time
import json
import hmac
import base64
import hashlib
import struct
from urllib.parse import quote
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-auth-aes256")
LOG_FILE = os.path.join(BASE_DIR, "logs/auth_security.jsonl")

def generate_base32_secret(length_bytes: int = 20) -> str:
    raw = os.urandom(length_bytes)
    return base64.b32encode(raw).decode("utf-8").rstrip("=")

def pad_b32(secret: str) -> bytes:
    rem = len(secret) % 8
    padded = secret + ("=" * ((8 - rem) % 8))
    return base64.b32decode(padded.upper())

def compute_totp(secret: str, for_time: int | None = None, period: int = 30, digits: int = 6) -> str:
    if for_time is None:
        for_time = int(time.time())
    counter = for_time // period
    key = pad_b32(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)

def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    now = int(time.time())
    for step in range(-window, window + 1):
        candidate = compute_totp(secret, for_time=now + (step * 30))
        if hmac.compare_digest(candidate, token.strip()):
            return True
    return False

def build_otpauth_uri(account_email: str, secret: str, issuer: str = "Internee.pk") -> str:
    label = quote(f"{issuer}:{account_email}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"

def main():
    email = "zain.tariq@example.test"
    secret = generate_base32_secret()
    uri = build_otpauth_uri(email, secret)
    live_code = compute_totp(secret)
    is_valid = verify_totp(secret, live_code)
    is_invalid_rejected = not verify_totp(secret, "000000")

    print(f"[2FA-TOTP] Account: {email}")
    print(f"[2FA-TOTP] Base32 Secret: {secret}")
    print(f"[2FA-TOTP] Google Authenticator URI: {uri}")
    print(f"[2FA-TOTP] Current 6-digit OTP: {live_code} | Valid={is_valid} | InvalidRejected={is_invalid_rejected}")

    with open(LOG_FILE, "a") as lf:
        lf.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "TOTP_2FA_VERIFIED",
            "account": email,
            "valid_check": is_valid,
            "invalid_rejected": is_invalid_rejected
        }) + "\n")

if __name__ == "__main__":
    main()

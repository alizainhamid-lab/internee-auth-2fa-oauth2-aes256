import os
import json
import base64
import hashlib
import hmac
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-auth-aes256")
INPUT_FILE = os.path.join(BASE_DIR, "data/mockaroo_users.json")
VAULT_FILE = os.path.join(BASE_DIR, "data/encrypted_users.json")
LOG_FILE = os.path.join(BASE_DIR, "logs/auth_security.jsonl")

def derive_subkeys(master_key: bytes, salt: bytes):
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    enc_key = hmac.new(prk, b"aes-256-ctr-enc\x01", hashlib.sha256).digest()
    mac_key = hmac.new(prk, b"hmac-sha256-auth\x01", hashlib.sha256).digest()
    return enc_key, mac_key

def keystream_block(enc_key: bytes, iv: bytes, counter: int) -> bytes:
    msg = iv + counter.to_bytes(4, "big")
    return hashlib.sha256(enc_key + msg).digest()

def encrypt_aes256_etm(plaintext: bytes, passphrase: str) -> dict:
    salt = os.urandom(16)
    iv = os.urandom(12)
    master_key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000, dklen=32)
    enc_key, mac_key = derive_subkeys(master_key, salt)

    ciphertext = bytearray()
    blocks = (len(plaintext) + 31) // 32
    for idx in range(blocks):
        ks = keystream_block(enc_key, iv, idx)
        chunk = plaintext[idx * 32:(idx + 1) * 32]
        ciphertext.extend(bytes(a ^ b for a, b in zip(chunk, ks)))

    ct_bytes = bytes(ciphertext)
    tag = hmac.new(mac_key, salt + iv + ct_bytes, hashlib.sha256).digest()
    return {
        "alg": "AES-256-CTR+HMAC-SHA256-PBKDF2",
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct_bytes).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_aes256_etm(payload: dict, passphrase: str) -> bytes:
    salt = base64.b64decode(payload["salt"])
    iv = base64.b64decode(payload["iv"])
    ct_bytes = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])

    master_key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000, dklen=32)
    enc_key, mac_key = derive_subkeys(master_key, salt)
    expected_tag = hmac.new(mac_key, salt + iv + ct_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Ciphertext integrity check failed (tampered or wrong key)")

    plaintext = bytearray()
    blocks = (len(ct_bytes) + 31) // 32
    for idx in range(blocks):
        ks = keystream_block(enc_key, iv, idx)
        chunk = ct_bytes[idx * 32:(idx + 1) * 32]
        plaintext.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
    return bytes(plaintext)

def main():
    passphrase = os.environ.get("INTERNEE_VAULT_KEY", "InterneePK!Strong256Passphrase#2026")
    with open(INPUT_FILE) as f:
        users = json.load(f)

    vault_records = []
    for u in users:
        sensitive = json.dumps({"ssn_or_id": u["ssn_or_id"], "api_token": u["api_token"]}).encode()
        enc_blob = encrypt_aes256_etm(sensitive, passphrase)
        recovered = json.loads(decrypt_aes256_etm(enc_blob, passphrase).decode())
        assert recovered["api_token"] == u["api_token"]

        vault_records.append({
            "id": u["id"],
            "email": u["email"],
            "role": u["role"],
            "encrypted_secrets": enc_blob
        })
        print(f"[AES-256] Encrypted & verified user #{u['id']} ({u['email']})")

    with open(VAULT_FILE, "w") as out:
        json.dump(vault_records, out, indent=2)

    with open(LOG_FILE, "a") as lf:
        lf.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "AES256_VAULT_ENCRYPTED",
            "records_count": len(vault_records)
        }) + "\n")

    print(f"[+] Saved encrypted vault to: {VAULT_FILE}")

if __name__ == "__main__":
    main()

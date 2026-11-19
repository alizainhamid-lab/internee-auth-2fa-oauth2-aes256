# Authentication Hardening (2FA + OAuth 2.0) & AES-256 Data Encryption

A Python security lab built on Kali Linux for an Internee.pk cybersecurity internship task.

## Modules & Artifacts
- `aes256_vault.py`: Encrypts and verifies sensitive user records from `data/mockaroo_users.json` into `data/encrypted_users.json` using AES-256 keystream + HMAC-SHA256 authentication.
- `totp_2fa.py`: Generates Base32 secrets, `otpauth://` Google Authenticator URIs, and verifies 6-digit TOTP codes with time-window tolerance.
- `oauth2_auth_flow.py`: Simulates OAuth 2.0 sign-in with PKCE code challenge verification and bearer/refresh token issuance.
- `auth_report.py`: Compiles security telemetry into `submission_summary.txt`.

## Author
Ali Zain Hamed - BS Cybersecurity (UET Lahore)

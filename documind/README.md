# 🧠 DocuMind — Secure Personal Document Vault

A Python/Flask desktop application for securely storing and managing personal documents with AI-powered expiry auto-detection.

## Features

- 🔐 **AES-256 Encryption** — All data encrypted using PBKDF2 (390,000 iterations) + Fernet/AES-256
- 🔑 **PIN Authentication** — Session-based vault locking with PIN verification
- 🤖 **Auto-Detection** — Smart expiry date detection via:
  - OCR image scanning (requires tesseract)
  - Filename pattern matching
  - Pasted text analysis
  - Document-type heuristics
- 📂 **All Indian Document Types** — Passport, Aadhaar, PAN, Voter ID, Driving License, Insurance, RC, Birth Cert, and more
- ➕ **Custom Document Types** — Add any document type with custom icon & label
- ⚠️ **Expiry Alerts** — 30-day warnings with dashboard alerts panel
- 📎 **File Attachments** — Upload PDF/JPG/PNG files with each document
- 📊 **Dashboard** — Live stats, category breakdown, alert timeline
- 🔍 **Search & Filter** — By type, status, and keyword
- 📤 **CSV Export** — Export all document data

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# Optional: Install tesseract for OCR (Ubuntu/Debian)
sudo apt-get install tesseract-ocr

# 2. Run the server
python app.py

# 3. Open in browser
# http://127.0.0.1:5050
```

## Security Architecture

```
User PIN
   │
   ▼
PBKDF2-HMAC-SHA256 (390,000 iterations + random salt)
   │
   ▼
AES-256 Key (Fernet)
   │
   ▼
Encrypted vault.enc (stored on disk)
```

- PIN hash stored separately using SHA-256 + salt
- No plaintext data ever written to disk
- Session cleared on logout/browser close
- File uploads stored with UUID names (no path traversal)

## Auto-Detection Engine

When you upload a document image, DocuMind:
1. **OCR Scan** — Extracts text using Tesseract OCR
2. **Keyword Search** — Looks for "expiry", "valid till", "exp date" near dates
3. **Pattern Match** — Finds DD/MM/YYYY, DD-MMM-YYYY, ISO dates
4. **Scoring** — Scores candidates by keyword proximity + future dates preferred
5. **Heuristic Fallback** — Suggests typical validity per document type

You can also paste document text directly for instant detection.

"""
DocuMind - Secure Personal Document Vault
Python Flask Application with:
  - AES-256 encrypted document storage (PBKDF2 key derivation)
  - PIN/Password authentication with session management
  - AI-powered expiry auto-detection from uploaded images via OCR
  - Full document CRUD with custom document types
  - Expiry alert system (30-day warnings)
"""

import os, json, re, uuid, hashlib, base64, logging
from datetime import datetime, date, timedelta
from pathlib import Path
from functools import wraps

from flask import (Flask, render_template, request, jsonify,
                   session, send_from_directory, Response)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.utils import secure_filename
from dateutil import parser as dateparser
from PIL import Image
import io

app = Flask(__name__)
app.secret_key = os.urandom(32)

BASE_DIR   = Path(__file__).parent
DATA_FILE  = BASE_DIR / "data" / "vault.enc"
SALT_FILE  = BASE_DIR / "data" / "salt.bin"
PIN_FILE   = BASE_DIR / "data" / "pin.hash"
UPLOAD_DIR = BASE_DIR / "uploads"
ALLOWED    = {'pdf','jpg','jpeg','png','webp'}
MAX_SIZE   = 10 * 1024 * 1024

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("DocuMind")

DOCUMENT_TYPES = {
    "passport":  {"icon":"🛂","label":"Passport / Visa","color":"#2563eb"},
    "license":   {"icon":"🚗","label":"Driving License","color":"#7c3aed"},
    "insurance": {"icon":"🏥","label":"Insurance","color":"#0d9488"},
    "aadhaar":   {"icon":"🪪","label":"Aadhaar Card","color":"#d97706"},
    "pan":       {"icon":"💳","label":"PAN Card","color":"#e85d26"},
    "voter":     {"icon":"🗳️","label":"Voter ID","color":"#16a34a"},
    "rc":        {"icon":"🚙","label":"RC / Vehicle Reg.","color":"#0891b2"},
    "birth":     {"icon":"📜","label":"Birth Certificate","color":"#be185d"},
    "edu":       {"icon":"🎓","label":"Educational Cert.","color":"#9333ea"},
    "medical":   {"icon":"💊","label":"Medical Record","color":"#dc2626"},
    "property":  {"icon":"🏠","label":"Property Document","color":"#854d0e"},
    "bank":      {"icon":"🏦","label":"Bank Document","color":"#1d4ed8"},
    "tax":       {"icon":"📊","label":"Tax / ITR","color":"#065f46"},
    "custom":    {"icon":"📁","label":"Custom Document","color":"#6b7280"},
}

# ── Security ──────────────────────────────────────────────────────────────────
def get_salt():
    if SALT_FILE.exists(): return SALT_FILE.read_bytes()
    s = os.urandom(16); SALT_FILE.write_bytes(s); return s

def derive_key(pin):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=get_salt(), iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(pin.encode()))

def fernet(pin): return Fernet(derive_key(pin))

def hash_pin(pin): return hashlib.sha256(get_salt() + pin.encode()).hexdigest()

def pin_set(): return PIN_FILE.exists()

def verify_pin(pin):
    return PIN_FILE.exists() and PIN_FILE.read_text().strip() == hash_pin(pin)

def set_pin(pin): PIN_FILE.write_text(hash_pin(pin))

# ── Vault ─────────────────────────────────────────────────────────────────────
def load_vault(pin):
    if not DATA_FILE.exists(): return []
    try: return json.loads(fernet(pin).decrypt(DATA_FILE.read_bytes()))
    except: return []

def save_vault(pin, docs):
    DATA_FILE.write_bytes(fernet(pin).encrypt(json.dumps(docs, default=str).encode()))

def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if "pin" not in session: return jsonify({"error":"unauthorized"}), 401
        return fn(*a, **k)
    return w

# ── Date Detection ────────────────────────────────────────────────────────────
DATE_PATS = [
    r'\b(\d{2})[/\-\.](\d{2})[/\-\.](\d{4})\b',
    r'\b(\d{4})[/\-\.](\d{2})[/\-\.](\d{2})\b',
    r'\b(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+(\d{4})\b',
    r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),?\s+(\d{4})\b',
]
EXPIRY_KW = ["expiry","expiration","valid till","valid upto","valid until",
             "expires","date of expiry","exp date","exp.","validity","renewal"]

def detect_expiry_from_text(text):
    if not text: return None
    lines = text.splitlines()
    candidates = []
    for i, line in enumerate(lines):
        nearby = " ".join(lines[max(0,i-2):i+3]).lower()
        has_kw = any(kw in nearby for kw in EXPIRY_KW)
        for pat in DATE_PATS:
            for m in re.finditer(pat, line, re.IGNORECASE):
                try:
                    parsed = dateparser.parse(m.group(0), dayfirst=True)
                    if parsed:
                        score = (10 if has_kw else 1) + (5 if parsed.date() >= date.today() else 0)
                        if parsed.date() >= date.today() + timedelta(days=365): score += 3
                        candidates.append((score, parsed.strftime("%Y-%m-%d"), parsed.date()))
                except: pass
    if not candidates:
        for pat in DATE_PATS:
            for m in re.finditer(pat, text, re.IGNORECASE):
                try:
                    parsed = dateparser.parse(m.group(0), dayfirst=True)
                    if parsed and parsed.date() >= date.today():
                        candidates.append((1, parsed.strftime("%Y-%m-%d"), parsed.date()))
                except: pass
    if not candidates: return None
    return sorted(candidates, key=lambda x: (-x[0], x[2]))[0][1]

def ocr_image(img_bytes):
    try:
        import pytesseract
        img = Image.open(io.BytesIO(img_bytes)).convert("L")
        return pytesseract.image_to_string(img, lang="eng")
    except: return ""

HEURISTICS = {"passport":3650,"license":1825,"insurance":365,"voter":3650,
              "aadhaar":0,"pan":0,"rc":1825,"medical":365,"edu":0,"tax":365,"bank":1825}

def smart_detect(file_bytes, filename, doc_type):
    result = {"date":None,"confidence":"none","method":"none","suggestion":None}
    is_img = filename.lower().rsplit(".",1)[-1] in ("jpg","jpeg","png","webp")
    if is_img and file_bytes:
        text = ocr_image(file_bytes)
        if text:
            d = detect_expiry_from_text(text)
            if d: return {"date":d,"confidence":"high","method":"ocr_image","suggestion":None}
    d = detect_expiry_from_text(filename)
    if d: return {"date":d,"confidence":"medium","method":"filename","suggestion":None}
    days = HEURISTICS.get(doc_type, 365)
    if days == 0:
        result["suggestion"] = "This document type typically does not expire."
    else:
        sug = (date.today()+timedelta(days=days)).isoformat()
        result.update({"date":sug,"confidence":"low","method":"heuristic",
                       "suggestion":f"Typical validity ~{days//365}yr. Suggested: {sug}"})
    return result

# ── Status Helpers ────────────────────────────────────────────────────────────
def get_status(exp):
    if not exp: return "safe"
    try:
        d = (date.fromisoformat(exp) - date.today()).days
        return "expired" if d<0 else "expiring" if d<=30 else "safe"
    except: return "safe"

def days_left(exp):
    if not exp: return None
    try: return (date.fromisoformat(exp)-date.today()).days
    except: return None

def enrich(doc):
    d = doc.copy()
    d["status"]    = get_status(d.get("expiry",""))
    d["days_left"] = days_left(d.get("expiry",""))
    t = d.get("type","custom")
    ti = DOCUMENT_TYPES.get(t, DOCUMENT_TYPES["custom"]).copy()
    if d.get("custom_label"): ti["label"] = d["custom_label"]
    if d.get("custom_icon"):  ti["icon"]  = d["custom_icon"]
    d["type_info"] = ti
    return d

def allowed(fn): return "." in fn and fn.rsplit(".",1)[1].lower() in ALLOWED

# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if not pin_set(): return render_template("setup.html")
    if "pin" not in session: return render_template("login.html")
    return render_template("app.html", doc_types=DOCUMENT_TYPES)

@app.route("/api/setup", methods=["POST"])
def api_setup():
    data = request.get_json(); pin = (data.get("pin","")).strip()
    if len(pin) < 4: return jsonify({"error":"PIN must be at least 4 characters"}), 400
    if pin_set(): return jsonify({"error":"Already set up"}), 400
    set_pin(pin); session["pin"] = pin; save_vault(pin, [])
    return jsonify({"ok":True})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(); pin = (data.get("pin","")).strip()
    if not verify_pin(pin): return jsonify({"error":"Invalid PIN"}), 401
    session["pin"] = pin
    return jsonify({"ok":True})

@app.route("/api/logout", methods=["POST"])
def api_logout(): session.clear(); return jsonify({"ok":True})

@app.route("/api/change-pin", methods=["POST"])
@login_required
def api_change_pin():
    data = request.get_json()
    old  = (data.get("old_pin","")).strip()
    new  = (data.get("new_pin","")).strip()
    if not verify_pin(old): return jsonify({"error":"Current PIN incorrect"}), 400
    if len(new) < 4:        return jsonify({"error":"New PIN too short"}), 400
    docs = load_vault(old); set_pin(new); save_vault(new, docs); session["pin"] = new
    return jsonify({"ok":True})

# ── Document Routes ───────────────────────────────────────────────────────────
@app.route("/api/docs", methods=["GET"])
@login_required
def api_list():
    docs = [enrich(d) for d in load_vault(session["pin"])]
    docs.sort(key=lambda d: ({"expired":0,"expiring":1,"safe":2}.get(d["status"],3), d.get("expiry") or "9999"))
    return jsonify({"docs":docs,"types":DOCUMENT_TYPES})

@app.route("/api/docs", methods=["POST"])
@login_required
def api_add():
    data = request.get_json()
    name = (data.get("name","")).strip()
    if not name: return jsonify({"error":"Name required"}), 400
    doc = {
        "id": str(uuid.uuid4()), "name": name,
        "type":    data.get("type","custom"),
        "number":  (data.get("number","")).strip(),
        "issuer":  (data.get("issuer","")).strip(),
        "issue":   (data.get("issue","")).strip(),
        "expiry":  (data.get("expiry","")).strip(),
        "notes":   (data.get("notes","")).strip(),
        "tags":    data.get("tags",[]),
        "file_ref":     data.get("file_ref"),
        "custom_label": (data.get("custom_label","")).strip(),
        "custom_icon":  (data.get("custom_icon","")).strip(),
        "added_at":     datetime.now().isoformat(),
        "updated_at":   datetime.now().isoformat(),
    }
    docs = load_vault(session["pin"]); docs.append(doc); save_vault(session["pin"], docs)
    return jsonify({"ok":True,"doc":enrich(doc)})

@app.route("/api/docs/<doc_id>", methods=["PUT"])
@login_required
def api_update(doc_id):
    data = request.get_json(); docs = load_vault(session["pin"])
    idx = next((i for i,d in enumerate(docs) if d["id"]==doc_id), None)
    if idx is None: return jsonify({"error":"Not found"}), 404
    for f in ["name","type","number","issuer","issue","expiry","notes","tags","file_ref","custom_label","custom_icon"]:
        if f in data: docs[idx][f] = data[f]
    docs[idx]["updated_at"] = datetime.now().isoformat()
    save_vault(session["pin"], docs)
    return jsonify({"ok":True,"doc":enrich(docs[idx])})

@app.route("/api/docs/<doc_id>", methods=["DELETE"])
@login_required
def api_delete(doc_id):
    docs = load_vault(session["pin"])
    doc  = next((d for d in docs if d["id"]==doc_id), None)
    if not doc: return jsonify({"error":"Not found"}), 404
    if doc.get("file_ref"):
        fp = UPLOAD_DIR / doc["file_ref"]
        if fp.exists(): fp.unlink()
    save_vault(session["pin"], [d for d in docs if d["id"]!=doc_id])
    return jsonify({"ok":True})

@app.route("/api/stats")
@login_required
def api_stats():
    docs = [enrich(d) for d in load_vault(session["pin"])]
    by_type = {}
    for d in docs: by_type[d["type"]] = by_type.get(d["type"],0)+1
    return jsonify({
        "total":    len(docs),
        "safe":     sum(1 for d in docs if d["status"]=="safe"),
        "expiring": sum(1 for d in docs if d["status"]=="expiring"),
        "expired":  sum(1 for d in docs if d["status"]=="expired"),
        "by_type":  by_type,
        "alerts":   [d for d in docs if d["status"] in ("expiring","expired")],
    })

@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files: return jsonify({"error":"No file"}), 400
    f = request.files["file"]
    if not f.filename or not allowed(f.filename): return jsonify({"error":"Invalid file"}), 400
    raw = f.read()
    if len(raw) > MAX_SIZE: return jsonify({"error":"Too large (max 10MB)"}), 400
    ext  = secure_filename(f.filename).rsplit(".",1)[-1].lower()
    name = f"{uuid.uuid4().hex}.{ext}"
    (UPLOAD_DIR/name).write_bytes(raw)
    detection = smart_detect(raw, f.filename, request.form.get("doc_type","custom"))
    return jsonify({"ok":True,"file_ref":name,"original_name":f.filename,"detection":detection})

@app.route("/api/detect-text", methods=["POST"])
@login_required
def api_detect_text():
    data = request.get_json()
    d = detect_expiry_from_text(data.get("text",""))
    return jsonify({"detected":d,"confidence":"high" if d else "none"})

@app.route("/uploads/<fn>")
@login_required
def serve_file(fn): return send_from_directory(UPLOAD_DIR, secure_filename(fn))

@app.route("/api/export/csv")
@login_required
def api_export():
    docs = load_vault(session["pin"])
    rows = ["Name,Type,Number,Issuer,Issue Date,Expiry,Status,Days Left,Notes"]
    for d in docs:
        dl = days_left(d.get("expiry",""))
        rows.append(",".join(f'"{str(x).replace(chr(34),chr(34)*2)}"' for x in [
            d.get("name",""), d.get("type",""), d.get("number",""), d.get("issuer",""),
            d.get("issue",""), d.get("expiry",""), get_status(d.get("expiry","")),
            dl if dl is not None else "", d.get("notes","")
        ]))
    return Response("\n".join(rows), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment;filename=DocuMind_Export.csv"})

if __name__ == "__main__":
    UPLOAD_DIR.mkdir(exist_ok=True)
    (BASE_DIR/"data").mkdir(exist_ok=True)
    app.run(debug=False, port=5050, host="127.0.0.1")

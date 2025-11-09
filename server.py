# server.py
from flask import Flask, request, jsonify
import os, json, hashlib, hmac, base64, datetime, threading, uuid

app = Flask(__name__)

# ======================
# Configuración (ENV VARS)
# ======================
SECRET = os.environ.get("DIBUTEK_SECRET", "DIBUTEK-LIC-SECRET-2025")  # Debe coincidir con tu app
TOKENS_FILE = os.environ.get("TOKENS_FILE", "tokens.json")
SINGLE_USE = os.environ.get("SINGLE_USE", "1") == "1"                # 1=token de un solo uso
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")                          # clave admin para endpoints /admin

_lock = threading.Lock()

# ======================
# Utilidades
# ======================
def load_tokens():
    if not os.path.exists(TOKENS_FILE):
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_tokens(tokens: dict):
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)

def sign_hex(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(body + SECRET.encode("utf-8")).hexdigest()

def sign_hmac_b64(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    sig = hmac.new(SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("utf-8")

def make_license(product: str, token: str, hwid: str) -> dict:
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    lic = {
        "product": product or "DIBUTEK Pro",
        "token": token,
        "hardware_id": hwid,
        "issued_at": now
    }
    # Firmas en dos formatos (tu app funciona con cualquiera: devuelvo ambos)
    lic["signature"] = sign_hmac_b64(lic)  # preferido: HMAC-SHA256 base64
    lic["_signature_hex"] = sign_hex(lic)  # compatibilidad: hex
    return lic

def require_admin(req) -> bool:
    if not ADMIN_KEY:
        return False
    return req.headers.get("X-Admin-Key", "") == ADMIN_KEY

# ======================
# Endpoints públicos
# ======================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": datetime.datetime.utcnow().isoformat() + "Z"})

@app.route("/api/activate", methods=["POST"])
def activate():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    hwid = (data.get("hardware_id") or "").strip()

    if not token or not hwid:
        return jsonify({"ok": False, "error": "Missing token or hardware_id"}), 400

    with _lock:
        tokens = load_tokens()
        entry = tokens.get(token)
        if not entry:
            return jsonify({"ok": False, "error": "Token inválido"}), 404
        if entry.get("disabled"):
            return jsonify({"ok": False, "error": "Token ya usado o deshabilitado"}), 403

        allowed_hwid = entry.get("allowed_hwid")
        if allowed_hwid and allowed_hwid != hwid:
            return jsonify({"ok": False, "error": "HWID no autorizado para este token"}), 403

        product = entry.get("product", "DIBUTEK Pro")
        lic = make_license(product, token, hwid)

        if SINGLE_USE:
            entry["disabled"] = True
            entry["used_at"] = datetime.datetime.utcnow().isoformat() + "Z"
            entry["used_by_hwid"] = hwid
            tokens[token] = entry
            save_tokens(tokens)

    lic_txt = json.dumps(lic, ensure_ascii=False)
    lic_b64 = base64.b64encode(lic_txt.encode("utf-8")).decode("utf-8")
    return jsonify({"ok": True, "license": lic, "license_b64": lic_b64})

# ======================
# Endpoints de administración (protegidos por X-Admin-Key)
# ======================
@app.route("/admin/create_token", methods=["POST"])
def admin_create_token():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip() or f"DIBU-{uuid.uuid4().hex[:8].upper()}-{datetime.datetime.utcnow().year}"
    product = (data.get("product") or "DIBUTEK Pro").strip()
    allowed_hwid = (data.get("allowed_hwid") or "").strip() or None
    notes = (data.get("notes") or "").strip()

    with _lock:
        tokens = load_tokens()
        if token in tokens:
            return jsonify({"ok": False, "error": "Token ya existe"}), 409
        tokens[token] = {
            "product": product,
            "allowed_hwid": allowed_hwid,
            "notes": notes,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "disabled": False
        }
        save_tokens(tokens)

    return jsonify({"ok": True, "token": token})

@app.route("/admin/tokens", methods=["GET"])
def admin_list_tokens():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    tokens = load_tokens()
    return jsonify({"ok": True, "count": len(tokens), "tokens": tokens})

@app.route("/admin/disable_token", methods=["POST"])
def admin_disable_token():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Falta token"}), 400

    with _lock:
        tokens = load_tokens()
        if token not in tokens:
            return jsonify({"ok": False, "error": "Token no existe"}), 404
        tokens[token]["disabled"] = True
        tokens[token]["disabled_at"] = datetime.datetime.utcnow().isoformat() + "Z"
        save_tokens(tokens)
    return jsonify({"ok": True})

if __name__ == "__main__":
    # Desarrollo local
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

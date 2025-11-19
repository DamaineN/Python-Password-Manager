# modules/admin_invite.py
import os
import json
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional

from modules.encryption import DataManip

INVITES_FILE = "db/admin_invites.json"
INVITES_ENC = INVITES_FILE + ".enc"

def _ensure_invites_file():
    dm = DataManip()
    if not os.path.exists(INVITES_ENC):
        tmp = {}
        with open(INVITES_FILE, "w", encoding="utf-8") as f:
            json.dump(tmp, f, indent=4)
        dm.encrypt_json(INVITES_FILE)

def load_invites() -> dict:
    _ensure_invites_file()
    dm = DataManip()
    invites = dm.decrypt_json(INVITES_ENC) or {}
    return invites

def save_invites(invites: dict):
    dm = DataManip()
    with open(INVITES_FILE, "w", encoding="utf-8") as f:
        json.dump(invites, f, indent=4)
    dm.encrypt_json(INVITES_FILE)

def _now_iso():
    return datetime.utcnow().isoformat()

def _in_future_iso(minutes: int):
    return (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()

def _is_expired(expires_iso: str) -> bool:
    try:
        expires = datetime.fromisoformat(expires_iso)
        return datetime.utcnow() > expires
    except:
        return True

def _const_compare(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except:
        return a == b

def create_invite(created_by: str, ttl_minutes: int = 10) -> str:
    invites = load_invites()
    token = secrets.token_hex(16)  # 32 hex chars
    invites[token] = {
        "created_by": created_by,
        "created_at": _now_iso(),
        "expires_at": _in_future_iso(ttl_minutes),
        "used": False,
        "used_by": None,
        "used_at": None
    }
    save_invites(invites)
    return token

def validate_and_consume_invite(token: str, consume: bool = True) -> Optional[dict]:
    invites = load_invites()

    match_key = None
    for k in invites.keys():
        if _const_compare(k, token):
            match_key = k
            break

    if not match_key:
        return None

    rec = invites[match_key]

    if rec.get("used"):
        return None

    if _is_expired(rec["expires_at"]):
        invites.pop(match_key)
        save_invites(invites)
        return None

    if consume:
        rec["used"] = True
        rec["used_at"] = _now_iso()
        invites[match_key] = rec
        save_invites(invites)

    return rec

def revoke_invite(token: str) -> bool:
    invites = load_invites()
    if token in invites:
        invites.pop(token)
        save_invites(invites)
        return True
    return False

def list_invites() -> dict:
    return load_invites()

# main.py
import os
import json
import sys
import getpass
import hashlib
import time
import re
import uuid
from datetime import datetime, timedelta

from termcolor import colored
from halo import Halo

import pyotp

from modules.encryption import DataManip
from modules.exceptions import UserExits, PasswordFileDoesNotExist, AccountExists, InvalidCredentials, AccountLocked

USERS_FILE = "db/users.json"
PASSWORDS_FILE = "db/passwords.json"

# session & policy config
FAILED_ATTEMPTS = {}          # in-memory attempts (per run)
MAX_ATTEMPTS = 5              # when to apply lockout
LOCKOUT_DURATION_MIN = 15    # minutes of lockout
SESSION_TIMEOUT_MIN = 15     # session expiry after inactivity (minutes)

def ensure_db_dirs():
    try:
        os.mkdir("db")
    except FileExistsError:
        pass
    try:
        os.mkdir("logs")
    except FileExistsError:
        pass

def load_users():
    ensure_db_dirs()
    if not os.path.isfile(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def hash_password(password: str, salt_hex: str = None):
    """Return (hash_hex, salt_hex) using PBKDF2-HMAC-SHA256."""
    if salt_hex:
        salt = bytes.fromhex(salt_hex)
    else:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return dk.hex(), salt.hex()

def verify_password(stored_hash_hex: str, password: str, salt_hex: str):
    h, _ = hash_password(password, salt_hex)
    return h == stored_hash_hex

# Validate username: letters, numbers, underscore, 3-20 chars
def valid_username(u):
    return bool(re.match(r"^[A-Za-z0-9_]{3,20}$", u))

# Password policy: min 12 chars, upper, lower, digit, symbol
def check_password_policy(pw: str):
    if len(pw) < 12:
        return False, "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", pw):
        return False, "Include at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Include at least one lowercase letter."
    if not re.search(r"[0-9]", pw):
        return False, "Include at least one digit."
    if not re.search(r"[!@#$%^&*()\-_+=\[\]{};:'\",.<>/?\\|`~]", pw):
        return False, "Include at least one special character."
    return True, "OK"

def register():
    users = load_users()
    print(colored("Register new user (type 'exit' to cancel)", "green"))
    username = input("Enter username: ").strip()
    if username.lower() == "exit":
        raise UserExits
    if not valid_username(username):
        print(colored("Invalid username. Use 3-20 chars: letters, numbers, underscore.", "red"))
        return register()
    if username in users:
        print(colored("User already exists.", "red"))
        return

    password = getpass.getpass("Enter password: ")
    if password.lower().strip() == "exit":
        raise UserExits
    valid, msg = check_password_policy(password)
    if not valid:
        print(colored("Password policy violation: " + msg, "red"))
        return register()
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print(colored("Passwords do not match.", "red"))
        return register()

    # role selection (admin/user)
    role = input("Role (admin/user) [default: user]: ").strip().lower()
    if role not in ("admin", "user"):
        role = "user"

    # 2FA opt-in
    enable_2fa = input("Enable TOTP 2FA now? (Y/N) [recommended for admin]: ").strip().lower()
    if enable_2fa == 'y':
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name="SecureCLI-Passman")
        print(colored("Save this secret in your authenticator app (or scan). URI shown for convenience:", "yellow"))
        print(provisioning_uri)
    else:
        secret = None

    hashed, salt = hash_password(password)
    # store structure with lockout fields
    users[username] = {
        "password": hashed,
        "salt": salt,
        "role": role,
        "2fa_secret": secret,
        "failed_attempts": 0,
        "lockout_until": None
    }
    save_users(users)
    print(colored(f"User {username} created with role {role}. You may login now.", "green"))

def register_flow():
    try:
        register()
    except UserExits:
        print(colored("Registration cancelled.", "red"))

def login():
    users = load_users()
    username = input("Username (or 'register' to create account): ").strip()
    if username.lower() == 'register':
        register_flow()
        return None, None, None, None
    if username.lower() == "exit":
        raise UserExits
    if username not in users:
        print(colored("Unknown user. You can register.", "red"))
        return None, None, None, None

    # check persistent lockout
    rec = users[username]
    lock_until = rec.get("lockout_until")
    if lock_until:
        # stored as ISO timestamp string
        until_dt = datetime.fromisoformat(lock_until)
        if datetime.utcnow() < until_dt:
            remaining = (until_dt - datetime.utcnow()).total_seconds() // 60
            print(colored(f"Account locked. Try again in {int(remaining)+1} minutes.", "red"))
            return None, None, None, None
        else:
            # lock expired, reset
            rec["failed_attempts"] = 0
            rec["lockout_until"] = None
            save_users(users)

    # check attempts in-memory too
    if FAILED_ATTEMPTS.get(username, 0) >= MAX_ATTEMPTS:
        print(colored("Too many failed attempts this session. Try later.", "red"))
        return None, None, None, None

    password = getpass.getpass("Password: ")
    if password.lower().strip() == "exit":
        raise UserExits

    if verify_password(rec["password"], password, rec["salt"]):
        # reset attempts
        rec["failed_attempts"] = 0
        rec["lockout_until"] = None
        save_users(users)

        # derive key for AES using user's salt (use DataManip derive_key)
        dm = DataManip()
        key_bytes, _salt = dm.derive_key(password, rec["salt"])
        # if 2FA enabled, ask for TOTP
        if rec.get("2fa_secret"):
            totp = pyotp.TOTP(rec["2fa_secret"])
            code = input("Enter 6-digit 2FA code from authenticator: ").strip()
            if not totp.verify(code, valid_window=1):
                print(colored("Invalid 2FA code.", "red"))
                return None, None, None, None

        # create session token with expiry
        session_token = uuid.uuid4().hex
        session_expires = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MIN)
        # return username, role, key_bytes and session info
        print(colored(f"{dm.checkmark_} Welcome {username}! Role: {rec['role']}", "green"))
        return username, rec['role'], key_bytes, {"token": session_token, "expires_at": session_expires.isoformat()}
    else:
        # wrong password -> increment both persistent and in-memory counters
        rec["failed_attempts"] = rec.get("failed_attempts", 0) + 1
        FAILED_ATTEMPTS[username] = FAILED_ATTEMPTS.get(username, 0) + 1
        # if exceeded threshold, set persistent lockout
        if rec["failed_attempts"] >= MAX_ATTEMPTS:
            until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MIN)
            rec["lockout_until"] = until.isoformat()
            print(colored(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION_MIN} minutes.", "red"))
        else:
            print(colored("Invalid credentials.", "red"))
        save_users(users)
        return None, None, None, None

def exit_program():
    print(colored("Exiting...", "red"))
    sys.exit()

def start():
    ensure_db_dirs()
    obj = DataManip()

    print(colored("Welcome to Secure CLI Password Manager", "green"))
    while True:
        try:
            result = login()
            if isinstance(result, tuple) and len(result) == 4:
                username, role, key_bytes, session_info = result
                if username is None:
                    continue
                # pass session info into Manager
                from modules.menu import Manager
                menu = Manager(obj, PASSWORDS_FILE, username, role, key_bytes, session_info)
                try:
                    menu.begin()
                except UserExits:
                    exit_program()
            else:
                # login failed or action completed
                pass
        except UserExits:
            exit_program()

if __name__ == "__main__":
    start()

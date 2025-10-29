# main.py
import os
import json
import sys
import getpass
import hashlib
import time
import re

from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import UserExits, PasswordFileDoesNotExist, AccountExists, InvalidCredentials
from modules.menu import Manager

USERS_FILE = "db/users.json"
PASSWORDS_FILE = "db/passwords.json"

# simple in-memory attempt tracker per username (resets when program restarts)
FAILED_ATTEMPTS = {}
MAX_ATTEMPTS = 5

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
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return dk.hex(), salt.hex()

def verify_password(stored_hash_hex: str, password: str, salt_hex: str):
    h, _ = hash_password(password, salt_hex)
    return h == stored_hash_hex

# Validate username: letters, numbers, underscore, 3-20 chars
def valid_username(u):
    return bool(re.match(r"^[A-Za-z0-9_]{3,20}$", u))

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
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print(colored("Passwords do not match.", "red"))
        return register()

    # simple role selection (admin/user)
    role = input("Role (admin/user) [default: user]: ").strip().lower()
    if role not in ("admin", "user"):
        role = "user"

    hashed, salt = hash_password(password)
    users[username] = {"password": hashed, "salt": salt, "role": role}
    save_users(users)
    print(colored(f"User {username} created with role {role}. You may login now.", "green"))

def login():
    users = load_users()
    username = input("Username (or 'register' to create account): ").strip()
    if username.lower() == 'register':
        return register(), None, None
    if username.lower() == "exit":
        raise UserExits
    if username not in users:
        print(colored("Unknown user. You can register.", "red"))
        return None, None, None

    # check attempts
    if FAILED_ATTEMPTS.get(username, 0) >= MAX_ATTEMPTS:
        print(colored("Too many failed attempts this session. Try later.", "red"))
        raise UserExits

    password = getpass.getpass("Password: ")
    if password.lower().strip() == "exit":
        raise UserExits

    user_rec = users[username]
    if verify_password(user_rec["password"], password, user_rec["salt"]):
        # derive key for AES using same PBKDF2 salt but produce 16 bytes (done in DataManip.derive_key)
        dm = DataManip()
        key_bytes, _salt = dm.derive_key(password, user_rec["salt"])
        print(colored(f"{dm.checkmark_} Welcome {username}! Role: {user_rec['role']}", "green"))
        return username, user_rec['role'], key_bytes
    else:
        print(colored("Invalid credentials.", "red"))
        FAILED_ATTEMPTS[username] = FAILED_ATTEMPTS.get(username, 0) + 1
        return None, None, None

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
            if isinstance(result, tuple) and len(result) == 3:
                username, role, key_bytes = result
                if username is None:
                    continue
                menu = Manager(obj, PASSWORDS_FILE, username, role, key_bytes)
                try:
                    menu.begin()
                except UserExits:
                    exit_program()
            else:
                # register returned or cancelled
                pass
        except UserExits:
            exit_program()

if __name__ == "__main__":
    start()

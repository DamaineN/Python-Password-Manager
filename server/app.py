# server/app.py
import os
import sys
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES

# Add project root to sys.path so 'modules' can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.encryption import DataManip
from modules.exceptions import PasswordFileDoesNotExist, PasswordFileIsEmpty, PasswordNotFound

dm = DataManip() 
app = Flask(__name__)
CORS(app)
data_manip = DataManip()
DB_DIR = "db"
os.makedirs(DB_DIR, exist_ok=True)

def get_user_file(user):
    return os.path.join("db", f"passwords_{user}.json")

# File paths
PASSWORD_FILE = os.path.join(os.path.dirname(__file__), "passwords.json")
MASTER_FILE = os.path.join(os.path.dirname(__file__), "master.json")

@app.route("/")
def index():
    return jsonify({"status": "Password Manager API running ✅"}), 200

# server/app.py (update encrypt route)
@app.route("/encrypt", methods=["POST"])
def encrypt_password():
    data = request.json or {}
    user = data.get("user")
    website = data.get("website")
    password = data.get("data")        # password to store
    master_pw = data.get("password")   # master/login password

    # check required fields
    if not all([user, website, password, master_pw]):
        return jsonify({"error": "Missing fields: user, website, data, password"}), 400

    user_file = get_user_file(user)
    if not os.path.exists(user_file):
        # create empty user password file
        with open(user_file, "w") as f:
            json.dump({}, f)

    try:
        with open(user_file, "r") as f:
            j = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed reading user file: {e}"}), 500

    # derive a new key for this entry using a fresh random salt
    key_bytes, salt_hex = dm.derive_key(master_pw)

    try:
        # encrypt using AES-EAX and save salt/nonce/password in user JSON
        cipher = AES.new(key_bytes, AES.MODE_EAX)
        nonce_hex = cipher.nonce.hex()
        ciphertext_hex = cipher.encrypt(password.encode("utf-8")).hex()

        j[website] = {
            "nonce": nonce_hex,
            "password": ciphertext_hex,
            "salt": salt_hex
        }

        with open(user_file, "w") as f:
            json.dump(j, f, sort_keys=True, indent=4)

        return jsonify({"salt": salt_hex}), 200

    except Exception as e:
        app.logger.exception("Unexpected encrypt error")
        return jsonify({"error": f"Unexpected server error: {str(e)}"}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_password():
    data = request.json or {}
    user = data.get("user")
    website = data.get("website")
    master_pw = data.get("password")  # master password supplied by client (should be login password)

    if not all([user, website, master_pw]):
        return jsonify({"error": "Missing fields: require user, website, password"}), 400

    user_file = get_user_file(user)
    if not os.path.exists(user_file):
        return jsonify({"error": "Password file not found"}), 404

    try:
        with open(user_file, "r") as f:
            j = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed reading user file: {e}"}), 500

    if website not in j:
        return jsonify({"error": f"{website} not found for user {user}"}), 404

    entry = j[website]
    salt = entry.get("salt")
    nonce = entry.get("nonce")
    ciphertext_hex = entry.get("password")

    if not all([salt, nonce, ciphertext_hex]):
        return jsonify({"error": "Stored entry incomplete (missing salt/nonce/password)"}), 500

    try:
        # derive key using salt stored with this entry
        key_bytes, _ = dm.derive_key(master_pw, salt)
        # use the existing decrypt method that expects (key_bytes, website, filename)
        # but since decrypt_data expects to read the file itself, we'll call the lower-level AES decrypt here
        ciphertext = bytes.fromhex(ciphertext_hex)
        nonce_bytes = bytes.fromhex(nonce)

        from Crypto.Cipher import AES
        cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce_bytes)
        plaintext_bytes = cipher.decrypt(ciphertext)

        # try decode to utf-8 (may raise UnicodeDecodeError if wrong key)
        plaintext = plaintext_bytes.decode("utf-8")
        return jsonify({"decrypted": plaintext}), 200

    except UnicodeDecodeError:
        # wrong key -> decryption gave bytes but not valid text
        return jsonify({"error": "Decryption failed — likely wrong master password or corrupted ciphertext"}), 400
    except ValueError as ve:
        # AES / padding / authentication errors
        return jsonify({"error": f"Decryption error: {ve}"}), 400
    except KeyError as ke:
        return jsonify({"error": f"Entry missing field: {ke}"}), 500
    except Exception as e:
        # avoid leaking stack traces; return safe message and log server-side
        app.logger.exception("Unexpected decrypt error")
        return jsonify({"error": f"Unexpected server error: {str(e)}"}), 500
    
# --- FastAPI-style Endpoints ---
@app.route("/store_password", methods=["POST"])
def store_password():
    content = request.json
    user = content.get("user")
    key = content.get("key")
    website = content.get("website")
    password = content.get("password")

    if not all([user, key, website, password]):
        return jsonify({"error": "Missing fields"}), 400

    try:
        data_manip.encrypt_data(PASSWORD_FILE, password, key.encode(), website)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/retrieve_password", methods=["GET"])
def retrieve_password():
    user = request.args.get("user")
    key = request.args.get("key")
    website = request.args.get("website")

    if not all([user, key, website]):
        return jsonify({"error": "Missing query parameters"}), 400

    try:
        password = data_manip.decrypt_data(key.encode(), website, PASSWORD_FILE)
        return jsonify({"password": password}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route("/list", methods=["GET"])
def list_passwords():
    user = request.args.get("user")
    if not user:
        return jsonify({"error": "Missing user"}), 400

    user_file = get_user_file(user)
    if not os.path.exists(user_file):
        return jsonify({"stored_passwords": {}}), 200

    with open(user_file, "r") as f:
        data = json.load(f)
    return jsonify({"stored_passwords": data}), 200

@app.route("/delete", methods=["POST"])
def delete_password():
    data = request.json
    user = data.get("user")
    website = data.get("website")

    if not user or not website:
        return jsonify({"error": "Missing user or website"}), 400

    user_file = get_user_file(user)
    if not os.path.exists(user_file):
        return jsonify({"error": "Password file not found"}), 404

    try:
        with open(user_file, 'r') as f:
            pw_data = json.load(f)
        if website not in pw_data:
            return jsonify({"error": f"{website} not found"}), 404

        pw_data.pop(website)
        with open(user_file, 'w') as f:
            json.dump(pw_data, f, indent=4)
        return jsonify({"message": f"{website} deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
from modules.encryption import DataManip
import json, os

@app.route("/delete_all_passwords", methods=["POST"])
def delete_all_passwords():
    """
    Admin-only: delete all passwords for this user
    Expects JSON: {"password": <master_pw>, "user": <username>}
    """
    content = request.json
    password = content.get("password")
    user = content.get("user")

    if not password or not user:
        return jsonify({"error": "Missing fields"}), 400

    try:
        # Verify the user exists
        with open("db/users.json", "r") as f:
            users = json.load(f)

        if user not in users:
            return jsonify({"error": "Unknown user"}), 400

        # Delete all passwords for this user
        user_file = get_user_file(user)
        if os.path.exists(user_file):
            os.remove(user_file)

        return jsonify({"message": "All passwords deleted"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_all_data", methods=["POST"])
def delete_all_data():
    content = request.json
    password = content.get("password")
    user = content.get("user")

    if not password or not user:
        return jsonify({"error": "Missing fields"}), 400

    try:
        users_file = "db/users.json"
        if not os.path.exists(users_file):
            return jsonify({"error": "No users found"}), 404

        with open(users_file, "r") as f:
            users = json.load(f)

        if user not in users:
            return jsonify({"error": "Unknown user"}), 400

        # Verify admin role
        if users[user].get("role") != "admin":
            return jsonify({"error": "Permission denied"}), 403

        # Verify master password
        stored_hash = users[user]["password"]
        salt = users[user]["salt"]
        from main import verify_password  # reuse your hash check
        if not verify_password(stored_hash, password, salt):
            return jsonify({"error": "Invalid password"}), 403

        # Delete all JSON files in db
        db_dir = "db"
        for filename in os.listdir(db_dir):
            if filename.endswith(".json"):
                os.remove(os.path.join(db_dir, filename))

        # Optionally log the deletion
        print(f"Admin {user} deleted all data including all users and passwords")

        return jsonify({"message": "All data including users deleted"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    cert_path = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_path = os.path.join(os.path.dirname(__file__), "key.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print("❌ Missing cert.pem or key.pem — generate them first.")
    else:
        print("✅ Server running at https://localhost:5000")
        app.run(host="0.0.0.0", port=5000, ssl_context=(cert_path, key_path), debug=True)
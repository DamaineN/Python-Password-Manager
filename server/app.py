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
data_manip = DataManip()
app = Flask(__name__)
CORS(app)
data_manip = DataManip()
DB_DIR = "db"
os.makedirs(DB_DIR, exist_ok=True)

def get_user_file(user):
    # return base path (plaintext temp path). We'll always use .enc via helper.
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
    password = data.get("data")
    master_pw = data.get("password")
    if not all([user, website, password, master_pw]):
        return jsonify({"error": "Missing fields: user, website, data, password"}), 400

    user_file = get_user_file(user)
    enc_path = user_file + ".enc"
    try:
        # load existing (decrypt) or create empty dict if not present
        if os.path.exists(enc_path):
            j = dm.decrypt_json(enc_path)
        else:
            j = {}

        # derive per-entry key / salt
        key_bytes, salt_hex = dm.derive_key(master_pw)

        # AES-EAX encrypt entry
        cipher = AES.new(key_bytes, AES.MODE_EAX)
        nonce_hex = cipher.nonce.hex()
        ciphertext_hex = cipher.encrypt(password.encode("utf-8")).hex()

        j[website] = {"nonce": nonce_hex, "password": ciphertext_hex, "salt": salt_hex}

        # write plaintext temp then encrypt it
        tmp_path = user_file
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(j, f, sort_keys=True, indent=4)
        dm.encrypt_json(tmp_path)  # produces user_file + ".enc" and removes tmp_path

        return jsonify({"salt": salt_hex}), 200

    except Exception as e:
        app.logger.exception("Unexpected encrypt error")
        return jsonify({"error": f"Unexpected server error: {str(e)}"}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_password():
    data = request.json or {}
    user = data.get("user")
    website = data.get("website")
    master_pw = data.get("password")
    if not all([user, website, master_pw]):
        return jsonify({"error": "Missing fields: require user, website, password"}), 400

    user_file = get_user_file(user)
    enc_path = user_file + ".enc"
    if not os.path.exists(enc_path):
        return jsonify({"error": "Password file not found"}), 404

    try:
        j = dm.decrypt_json(enc_path)
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
        key_bytes, _ = dm.derive_key(master_pw, salt)
        ciphertext = bytes.fromhex(ciphertext_hex)
        nonce_bytes = bytes.fromhex(nonce)
        cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce_bytes)
        plaintext_bytes = cipher.decrypt(ciphertext)
        plaintext = plaintext_bytes.decode("utf-8")
        return jsonify({"decrypted": plaintext}), 200

    except UnicodeDecodeError:
        return jsonify({"error": "Decryption failed — likely wrong master password"}), 400
    except ValueError as ve:
        return jsonify({"error": f"Decryption error: {ve}"}), 400
    except Exception as e:
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
    enc_path = user_file + ".enc"
    if not os.path.exists(enc_path):
        return jsonify({"stored_passwords": {} }), 200

    try:
        data = dm.decrypt_json(enc_path)
        # return stored_passwords as-is (but note: this exposes non-sensitive metadata like site names)
        return jsonify({"stored_passwords": data}), 200
    except Exception as e:
        app.logger.exception("Failed to decrypt list")
        return jsonify({"error": "Failed to read stored passwords"}), 500

@app.route("/delete", methods=["POST"])
def delete_password():
    data = request.json
    user = data.get("user")
    website = data.get("website")
    if not user or not website:
        return jsonify({"error": "Missing user or website"}), 400

    user_file = get_user_file(user)
    enc_path = user_file + ".enc"
    if not os.path.exists(enc_path):
        return jsonify({"error": "Password file not found"}), 404

    try:
        j = dm.decrypt_json(enc_path)
        if website not in j:
            return jsonify({"error": f"{website} not found"}), 404
        j.pop(website)
        tmp_path = user_file
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(j, f, indent=4)
        dm.encrypt_json(tmp_path)
        return jsonify({"message": f"{website} deleted"}), 200
    except Exception as e:
        app.logger.exception("delete error")
        return jsonify({"error": str(e)}), 500
    
from modules.encryption import DataManip
import json, os

@app.route("/delete_all_passwords", methods=["POST"])
def delete_all_passwords():
    content = request.json
    password = content.get("password")
    user = content.get("user")
    if not password or not user:
        return jsonify({"error": "Missing fields"}), 400
    try:
        users_enc = "db/users.json.enc"
        if not os.path.exists(users_enc):
            return jsonify({"error": "No users found"}), 404
        users = dm.decrypt_json(users_enc)
        if user not in users:
            return jsonify({"error": "Unknown user"}), 400
        user_file = get_user_file(user)
        enc_path = user_file + ".enc"
        if os.path.exists(enc_path):
            os.remove(enc_path)
        return jsonify({"message": "All passwords deleted"}), 200
    except Exception as e:
        app.logger.exception("delete_all_passwords")
        return jsonify({"error": str(e)}), 500

@app.route("/delete_all_data", methods=["POST"])
def delete_all_data():
    content = request.json
    password = content.get("password")
    user = content.get("user")
    if not password or not user:
        return jsonify({"error": "Missing fields"}), 400
    try:
        users_enc = "db/users.json.enc"
        if not os.path.exists(users_enc):
            return jsonify({"error": "No users found"}), 404
        users = dm.decrypt_json(users_enc)
        if user not in users:
            return jsonify({"error": "Unknown user"}), 400
        if users[user].get("role") != "admin":
            return jsonify({"error": "Permission denied"}), 403
        # verify master pw
        stored_hash = users[user]["password"]
        salt = users[user]["salt"]
        from main import verify_password
        if not verify_password(stored_hash, password, salt):
            return jsonify({"error": "Invalid password"}), 403

        # remove all .enc files in db
        db_dir = "db"
        for filename in os.listdir(db_dir):
            if filename.endswith(".enc"):
                os.remove(os.path.join(db_dir, filename))
        # also remove users.json.enc
        if os.path.exists(users_enc):
            os.remove(users_enc)

        print(f"Admin {user} deleted all data including all users and passwords")
        return jsonify({"message": "All data including users deleted"}), 200
    except Exception as e:
        app.logger.exception("delete_all_data")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    cert_path = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_path = os.path.join(os.path.dirname(__file__), "key.pem")

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print("Missing cert.pem or key.pem — generate them first using server/servercerts.py.")
    else:
        print("Server running at https://localhost:5000")
        app.run(host="0.0.0.0", port=5000, ssl_context=(cert_path, key_path), debug=True)
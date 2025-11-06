# modules/encryption.py
import json
import os
import random
import string
import hashlib
import threading
import time
import requests

from Crypto.Cipher import AES
from termcolor import colored
from halo import Halo
from cryptography.fernet import Fernet
from modules.exceptions import PasswordFileDoesNotExist, PasswordFileIsEmpty, PasswordNotFound

class ServerAPI:
    def __init__(self, base_url="https://localhost:5000"):
        self.base_url = base_url
        self.verify = "cert.pem"  # path to your server cert
        
    def encrypt_data(self, password, website, data):
        resp = requests.post(
            f"{self.base_url}/encrypt",
            json={"password": password, "website": website, "data": data},
            verify=self.verify
        )
        resp.raise_for_status()
        return resp.json()

    def decrypt_data(self, password, website, salt):
        resp = requests.post(
            f"{self.base_url}/decrypt",
            json={"password": password, "website": website, "salt": salt},
            verify=self.verify
        )
        resp.raise_for_status()
        return resp.json()["decrypted"]

    def list_passwords(self, filename):
        enc_path = filename + ".enc" if not filename.endswith(".enc") else filename
        pass_list = self.decrypt_json(enc_path)

        passwords_lst = ""
        for i in pass_list:
            passwords_lst += f"--{i}\n"

        if not passwords_lst:
            raise PasswordFileIsEmpty
        return passwords_lst

    def delete_password(self, website):
        resp = requests.post(
            f"{self.base_url}/delete",
            json={"website": website},
            verify=self.verify
        )
        resp.raise_for_status()
        return resp.json()

class DataManip:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]}
        self.checkmark_ = "\u2713"
        self.x_mark_ = "\u2717"
        self.specialChar_ = "!@#$%^&*()-_"
        self._fernet = self._get_system_key()

    def _get_system_key(self):
        """
        Generates or retrieves a persistent system encryption key.
        The key is stored in a hidden folder within the user's home directory.
        """
        key_dir = os.path.join(os.path.expanduser("~"), ".syskey")
        key_path = os.path.join(key_dir, "system.key")
        os.makedirs(key_dir, exist_ok=True)

        # Make it hidden on Windows
        if os.name == "nt":
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            ctypes.windll.kernel32.SetFileAttributesW(key_dir, FILE_ATTRIBUTE_HIDDEN)
        else:
            # Restrict access on Linux/macOS
            os.chmod(key_dir, 0o700)
    
        if not os.path.exists(key_path):
            key = Fernet.generate_key()
            with open(key_path, "wb") as f:
                f.write(key)

            # Hide the file on Windows
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(key_path, FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass
        else:
            with open(key_path, "rb") as f:
                key = f.read()

        return Fernet(key)

    def encrypt_json(self, json_path: str):
        """Encrypt a JSON file in-place and remove plaintext."""
        if not os.path.exists(json_path):
            return

        with open(json_path, "r", encoding="utf-8") as f:
            data = f.read()

        encrypted = self._fernet.encrypt(data.encode("utf-8"))
        enc_path = json_path + ".enc"
        with open(enc_path, "wb") as f:
            f.write(encrypted)

        try:
            os.remove(json_path)
        except Exception:
            pass

        return enc_path

    def decrypt_json(self, enc_path: str):
        """Decrypt an encrypted JSON file (.enc) and return data as dict."""
        if not os.path.exists(enc_path):
            raise PasswordFileDoesNotExist

        with open(enc_path, "rb") as f:
            encrypted_data = f.read()

        decrypted = self._fernet.decrypt(encrypted_data)
        return json.loads(decrypted.decode("utf-8"))
    
    # --- Key derivation helpers ---
    @staticmethod
    def derive_key(password: str, salt_hex: str = None):
        """
        Derive a 16-byte AES key from password using PBKDF2-HMAC-SHA256.
        Returns (key_bytes, salt_hex)
        """
        if salt_hex:
            salt = bytes.fromhex(salt_hex)
        else:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=16)
        return key, salt.hex()

    # --- Internal save helper ---
    def __save_password(self, filename, data_hex, nonce_hex, website):
        spinner = Halo(text=colored("Saving", "green"), spinner=self.dots_, color="green")
        spinner.start()
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as jsondata:
                    jfile = json.load(jsondata)
                jfile[website]["nonce"] = nonce_hex
                jfile[website]["password"] = data_hex
                with open(filename, 'w') as jsondata:
                    json.dump(jfile, jsondata, sort_keys=True, indent=4)
            except KeyError:
                with open(filename, 'r') as jsondata:
                    jfile = json.load(jsondata)
                jfile[website] = {}
                jfile[website]["nonce"] = nonce_hex
                jfile[website]["password"] = data_hex
                with open(filename, 'w') as jsondata:
                    json.dump(jfile, jsondata, sort_keys=True, indent=4)
        else:
            jfile = {website: {}}
            jfile[website]["nonce"] = nonce_hex
            jfile[website]["password"] = data_hex
            with open(filename, 'w') as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)
        
        self.encrypt_json(filename)
        spinner.stop()
        print(colored(f"{self.checkmark_} Saved successfully. Thank you!", "green"))

    # --- Encryption using derived key (16 bytes) ---
    def encrypt_data(self, filename: str, data: str, key_bytes: bytes, website: str):
        """
        Encrypts 'data' using AES-EAX and stores hex output + nonce hex into JSON filename.
        key_bytes must be a 16-byte key derived from user's password.
        """
        cipher = AES.new(key_bytes, AES.MODE_EAX)
        nonce_hex = cipher.nonce.hex()
        encrypted_data = cipher.encrypt(data.encode("utf-8")).hex()
        # persist
        self.__save_password(filename, encrypted_data, nonce_hex, website)

    def decrypt_data(self, key_bytes: bytes, website: str, filename: str):
        """Return a decrypted password as a string using provided key_bytes."""
        enc_path = filename + ".enc" if not filename.endswith(".enc") else filename
        jfile = self.decrypt_json(enc_path)

        try:
            nonce = bytes.fromhex(jfile[website]["nonce"])
            password = bytes.fromhex(jfile[website]["password"])
        except KeyError:
            raise PasswordNotFound

        cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
        plaintext_password = cipher.decrypt(password).decode("utf-8")
        return plaintext_password

    # --- Other helpers remain similar ---
    def generate_password(self):
        password = []
        length = input("Enter Length for Password (At least 8): ")

        if length.lower().strip() == "exit":
            raise Exception("UserExits")
        elif length.strip() == "":
            raise Exception("EmptyField")
        elif int(length) < 8:
            raise Exception("PasswordNotLongEnough")
        else:
            spinner = Halo(text=colored("Generating Password", "green"), spinner=self.dots_, color="green")
            spinner.start()
            for i in range(0, int(length)):
                password.append(random.choice(random.choice([string.ascii_lowercase, string.ascii_uppercase, string.digits, self.specialChar_])))
            finalPass = "".join(password)
            spinner.stop()
            return finalPass

    def list_passwords(self, filename):
        enc_path = filename + ".enc" if not filename.endswith(".enc") else filename
        if not os.path.exists(enc_path):
            raise PasswordFileDoesNotExist

        jfile = self.decrypt_json(enc_path)
        if not jfile:
            raise PasswordFileIsEmpty

        return "\n".join(f"--{site}" for site in jfile)

    def delete_db(self, filename):
        """Delete only password file contents and remove file."""
        if os.path.isfile(filename):
            spinner = Halo(text=colored("Deleting all password data...", "red"), spinner=self.dots_, color="red")
            jfile = {}
            with open(filename, 'w') as jdata:
                json.dump(jfile, jdata)
            os.remove(filename)
            spinner.stop()
        else:
            raise PasswordFileDoesNotExist

    def delete_password(self, filename, website):
        enc_path = filename + ".enc" if not filename.endswith(".enc") else filename
        if not os.path.exists(enc_path):
            raise PasswordFileDoesNotExist

        jfile = self.decrypt_json(enc_path)
        try:
            jfile.pop(website)
        except KeyError:
            raise PasswordNotFound

        # write and re-encrypt
        temp_json = filename if filename.endswith(".json") else filename + ".json"
        with open(temp_json, "w") as f:
            json.dump(jfile, f, indent=4)
        self.encrypt_json(temp_json)


    def delete_all_passwords(self, user):
        filename = f"db/passwords_{user}.json"
        if os.path.exists(filename):
            os.remove(filename)
        else:
            raise FileNotFoundError("Password file not found")



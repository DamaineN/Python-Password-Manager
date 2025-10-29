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

    def list_passwords(self):
        resp = requests.get(f"{self.base_url}/list", verify=self.verify)
        resp.raise_for_status()
        return resp.json()["stored_passwords"]

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
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as jdata:
                    jfile = json.load(jdata)
                nonce = bytes.fromhex(jfile[website]["nonce"])
                password = bytes.fromhex(jfile[website]["password"])
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

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
        if os.path.isfile(filename):
            with open(filename, 'r') as jsondata:
                pass_list = json.load(jsondata)
            passwords_lst = ""
            for i in pass_list:
                passwords_lst += "--{}\n".format(i)
            if passwords_lst == "":
                raise PasswordFileIsEmpty
            else:
                return passwords_lst
        else:
            raise PasswordFileDoesNotExist

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
        if os.path.isfile(filename):
            with open(filename, 'r') as jdata:
                jfile = json.load(jdata)
            try:
                jfile.pop(website)
                with open(filename, 'w') as jdata:
                    json.dump(jfile, jdata, sort_keys=True, indent=4)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist

    def delete_all_passwords(self, user):
        filename = f"db/passwords_{user}.json"
        if os.path.exists(filename):
            os.remove(filename)
        else:
            raise FileNotFoundError("Password file not found")



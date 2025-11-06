# modules/menu.py
import sys
import getpass
import pyperclip
import re
import threading
import time
import logging
import json
from datetime import datetime, timedelta
import requests
import os

from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import *

SERVER_URL = "https://localhost:5000"
SERVER_CERT = "server/cert.pem"

LOGFILE = "logs/activity.log"
SESSION_TIMEOUT_MIN = 15  # must match main's SESSION_TIMEOUT_MIN

# Initialize logging (module-level)
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Manager:
    """
    Arguments: 
        obj {DataManip}
        filename {str}
        user {str}
        role {str}
        key_bytes {bytes} - derived AES key for this user session
    """
    def __init__(self, obj: DataManip, filename: str, user: str, role: str, key_bytes: bytes, master_password: str,
                 session_info: dict, encrypt_fn=None, decrypt_fn=None):
        self.obj_ = obj
        self.filename_ = filename
        self.user_ = user
        self.role_ = role
        self.master_pw_ = master_password  # string from user input
        self.key_ = DataManip.derive_key(master_password)[0]  # bytes
        self.salts = {}  # store salt per website

        # Validate session info structure
        try:
            self.session_token = session_info.get("token")
            expires_raw = session_info.get("expires_at")
            self.session_expires = datetime.fromisoformat(expires_raw) if expires_raw else datetime.now()
        except Exception as e:
            logging.error(f"Session info invalid: {e}")
            self.session_token = None
            self.session_expires = datetime.now()
            
        # optional overrides
        self.encrypt_fn = encrypt_fn
        self.decrypt_fn = decrypt_fn

    def begin(self):
        try:
            choice = self.menu_prompt()
        except UserExits:
            raise UserExits
        except Exception as e:
            logging.error(f"Menu input error: {e}")
            print(colored("Invalid input or unexpected error. Please try again.", "red"))
            return self.begin()

        # populate salts on menu begin (best-effort)
        try:
            self._populate_salts_from_server()
        except Exception as e:
            logging.warning(f"Failed to populate salts: {e}")

        # Validate menu choice
        valid_choices = {'1', '2', '3', '4', '5', '6', '7'}
        if choice not in valid_choices:
            print(colored("Invalid menu option. Please select 1–7.", "red"))
            return self.begin()

        if choice == '4':  # User Exits
            print(colored("Exiting program...", "red"))
            sys.exit()

        if choice == '1':  # add or update a password
            try:
                self.update_db()
            except UserExits:
                raise
            except Exception as e:
                logging.error(f"Error updating DB: {e}")
                print(colored("An error occurred while updating password. Please try again.", "red"))
            return self.begin()

        elif choice == '2':  # look up a stored password
            try:
                website, password = self.load_password()
                if not website or not password:
                    print(colored("No password found or invalid data returned.", "red"))
                    return self.begin()

                print(colored(f"Password for {website}: {password}", "yellow"))

                try:
                    copy_to_clipboard = input("Copy password to clipboard? (Y/N): ").strip().lower()
                except EOFError:
                    print(colored("Input interrupted. Returning to menu.", "red"))
                    return self.begin()
                except Exception as e:
                    logging.error(f"Clipboard prompt error: {e}")
                    print(colored("Invalid input. Returning to menu.", "red"))
                    return self.begin()

                if copy_to_clipboard == "exit":
                    raise UserExits
                elif copy_to_clipboard == 'y':
                    try:
                        pyperclip.copy(password)
                        logging.info(f"{self.user_} copied password for {website}")
                        threading.Thread(target=self._clear_clipboard_later, daemon=True).start()
                        print(colored(f"{self.obj_.checkmark_} Password copied to clipboard (will clear after 30s)", "green"))
                    except pyperclip.PyperclipException:
                        print(colored(f"{self.obj_.x_mark_} Clipboard not available {self.obj_.x_mark_}", "red"))
                    except Exception as e:
                        logging.error(f"Clipboard copy failed: {e}")
                        print(colored("Unexpected error copying password to clipboard.", "red"))

            except UserExits:
                raise
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}", "red"))
            except Exception as e:
                logging.error(f"Error during password lookup: {e}")
                print(colored("An error occurred while retrieving password. Please try again.", "red"))
            return self.begin()

        elif choice == '3':  # Delete a single password
            try:
                return self.delete_password()
            except UserExits:
                raise
            except Exception as e:
                logging.error(f"Error deleting password: {e}")
                print(colored("An error occurred while deleting password. Please try again.", "red"))
                return self.begin()

        elif choice == '5':  # Delete DB of Passwords
            if self.role_ != 'admin':
                print(colored("Permission denied: Admin only.", "red"))
                return self.begin()
            try:
                self.delete_db()
            except MasterPasswordIncorrect:
                print(colored(f"{self.obj_.x_mark_} Master password is incorrect {self.obj_.x_mark_}", "red"))
            except UserExits:
                raise
            except Exception as e:
                logging.error(f"Error deleting DB: {e}")
                print(colored("An unexpected error occurred while deleting DB.", "red"))
            return self.begin()

        elif choice == '6':  # delete ALL data (admin)
            if self.role_ != 'admin':
                print(colored("Permission denied: Admin only.", "red"))
                return self.begin()
            try:
                self.delete_all_data()
            except MasterPasswordIncorrect:
                print(colored(f"{self.obj_.x_mark_} Master password is incorrect {self.obj_.x_mark_}", "red"))
            except UserExits:
                raise
            except Exception as e:
                logging.error(f"Error deleting all data: {e}")
                print(colored("An unexpected error occurred while deleting all data.", "red"))
            return self.begin()

        elif choice == '7':  # admin: view logs
            if self.role_ != 'admin':
                print(colored("Permission denied: Admin only.", "red"))
                return self.begin()
            try:
                self.view_logs()
            except Exception as e:
                logging.error(f"Error viewing logs: {e}")
                print(colored("Failed to read logs.", "red"))
            return self.begin()


    def menu_prompt(self):
        print(colored("\n\t*Enter 'exit' at any point to exit.*\n", "magenta"))
        print(colored("1) Add/Update a password", "blue"))
        print(colored("2) Look up a stored password", "blue"))
        print(colored("3) Delete a password", "blue"))
        print(colored("4) Exit program", "blue"))
        print(colored("5) Erase all passwords (admin)", "red"))
        print(colored("6) Delete all data including user accounts (admin)", "red"))
        print(colored("7) View audit logs (admin)", "yellow"))

        choice = input("Enter a choice: ")

        if choice == "":
            return self.menu_prompt()
        elif choice.lower() == "exit":
            raise UserExits
        else:
            return choice.strip()

    def _clear_clipboard_later(self, delay_seconds: int = 30):
        import pyperclip
        time.sleep(delay_seconds)
        try:
            pyperclip.copy("")
            logging.info(f"{self.user_} clipboard cleared after delay")
        except Exception:
            pass

    def __return_generated_password(self, website):
        try:
            generated_pass = self.obj_.generate_password()
            print(colored(generated_pass, "yellow"))

            loop = input("Generate a new password? (Y/N): ")
            if loop.lower().strip() == "exit":
                raise UserExits
            elif (loop.lower().strip() == 'y') or (loop.strip() == "") :
                return self.__return_generated_password(website)
            elif loop.lower().strip() == 'n':
                return generated_pass
        except (PasswordNotLongEnough, EmptyField):
            print(colored("Password length invalid.", "red"))
            return self.__return_generated_password(website)
        except UserExits:
            print(colored("Exiting...", "red"))
            sys.exit()

    # --- input validation for website names
    def _validate_website(self, website: str):
        # simple validation: hostname-like (letters, digits, ., -)
        if not website or not re.match(r"^[A-Za-z0-9\.\-]{2,253}$", website):
            return False
        return True

    def _populate_salts_from_server(self):
        """Fetch website->salt mapping from server and populate self.salts."""
        try:
            resp = requests.get(f"{SERVER_URL}/list", verify=SERVER_CERT, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            stored = data.get("stored_passwords", {})
            # stored is {website: salt_hex} or {} if none
            # convert None to missing (keep self.salts as simple map)
            for w, s in stored.items():
                if s:
                    self.salts[w] = s
            return True
        except Exception:
            # best-effort: ignore errors (server might be down)
            return False

    def update_db(self):
        website = input("Enter the website for which you want to store a password (ex. google.com): ").strip()
        if website.lower() == "":
            self.update_db()
        elif website.lower().strip() == "exit":
            raise UserExits
        elif not self._validate_website(website):
            print(colored("Invalid website name. Avoid special characters.", "red"))
            return self.update_db()
        else:
            gen_question = input("Do you want to generate a password for {} ? (Y/N): ".format(website))
            if gen_question.strip() == "":
                self.update_db()
            elif gen_question.lower().strip() == "exit":
                raise UserExits
            elif gen_question.lower().strip() == 'n':
                password = input("Enter a password for {}: ".format(website))
                if password.lower().strip() == "exit":
                    raise UserExits
                else:
                    # simple password strength hint (not enforced)
                    if len(password) < 8:
                        print(colored("Warning: password shorter than 8 characters.", "yellow"))
                        self._server_encrypt(website, password)
                        logging.info(f"{self.user_} stored/updated password for {website}")
            elif gen_question.lower().strip() == 'y':
                password = self.__return_generated_password(website)
                self._server_encrypt(website, password)
                logging.info(f"{self.user_} generated and stored password for {website}")

    def load_password(self):
        website = input("Enter website for the password you want to retrieve: ").strip()
        if website.lower() == "exit":
            raise UserExits
        elif website.strip() == "":
            return self.load_password()
        
        try:
            stored_websites = self._server_list_passwords()
            if website not in stored_websites:
                print(colored(f"✗ {website} not found on server for user {self.user_}", "red"))
                return self.load_password()
            
            plaintext = self._server_decrypt(website)
            if not plaintext:
                print(colored(f"✗ Failed to decrypt password for {website}", "red"))
                return self.load_password()
                
            logging.info(f"{self.user_} retrieved password for {website}")
            return website, plaintext  # <-- return a tuple instead of just plaintext

        except requests.HTTPError as e:
            print(colored(f"✗ Server error: {e}", "red"))
            return self.load_password()
        except Exception as e:
            print(colored(f"✗ Unexpected error: {e}", "red"))
            return self.load_password()


    def delete_db(self):
        confirmation = input("Are you sure you want to delete the password file? (Y/N) ")
        if confirmation.lower().strip() == 'y':
            try:
                self.obj_.delete_db(self.filename_)
                logging.warning(f"{self.user_} deleted password DB")
                print(colored(f"{self.obj_.checkmark_} Password Data Deleted successfully. {self.obj_.checkmark_}", "green"))
                return self.begin()
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}", "red"))
                return self.begin()
        elif confirmation.lower().strip() == 'n':
            print(colored("Cancelling...", "red"))
            return self.begin()
        elif confirmation.lower().strip() == "exit":
            raise UserExits
        elif confirmation.strip() == "":
            return self.delete_db()

    def list_passwords(self):
        print(colored("Current Passwords Stored:", "yellow"))
        spinner = Halo(text=colored("Loading Passwords", "yellow"), color="yellow", spinner=self.obj_.dots_)
        try:
            lst_of_passwords = self.obj_.list_passwords(self.filename_)
            spinner.stop()
            print(colored(lst_of_passwords, "yellow"))
        except PasswordFileIsEmpty:
            lst_of_passwords = "--There are no passwords stored.--"
            spinner.stop()
            print(colored(lst_of_passwords, "yellow"))
            raise PasswordFileIsEmpty
        except PasswordFileDoesNotExist:
            raise PasswordFileDoesNotExist

    def delete_password(self):
        website = input("What website do you want to delete? (ex. google.com): ").strip()
        if website.lower() == "exit":
            raise UserExits
        elif website.strip() == "":
            return self.delete_password()
        else:
            payload = {
                "user": self.user_,       # <-- include user
                "website": website
            }
            try:
                resp = requests.post(f"{SERVER_URL}/delete", json=payload, verify=SERVER_CERT)
                resp.raise_for_status()
                print(colored(f"✓ Password for {website} deleted successfully from server.", "green"))
                logging.warning(f"{self.user_} deleted password for {website} from server")
                # Remove salt from local memory if present
                self.salts.pop(website, None)
                return self.begin()
            except requests.HTTPError as e:
                if resp.status_code == 404:
                    print(colored(f"{self.obj_.x_mark_} {website} not found on server {self.obj_.x_mark_}", "red"))
                else:
                    print(colored(f"✗ Server delete failed: {e}\nResponse content: {resp.text}", "red"))
                return self.delete_password()
            except Exception as e:
                print(colored(f"✗ Server delete failed: {e}", "red"))
                return self.delete_password()

    def delete_db(self):
        confirmation = input("Are you sure you want to delete ALL passwords? (Y/N): ").strip().lower()
        if confirmation == 'y':
            payload = {
                "password": self.master_pw_,
                "user": self.user_
            }
            try:
                resp = requests.post(f"{SERVER_URL}/delete_all_passwords", json=payload, verify=SERVER_CERT)
                resp.raise_for_status()
                logging.warning(f"{self.user_} deleted ALL passwords from server")
                print(colored(f"✓ All passwords deleted successfully from server. {self.obj_.checkmark_}", "green"))
                # Clear local salts since all passwords are gone
                self.salts.clear()
            except requests.HTTPError as e:
                print(colored(f"✗ Server delete all passwords failed: {e}\nResponse content: {resp.text}", "red"))
            except Exception as e:
                print(colored(f"✗ Unexpected error while deleting all passwords: {e}", "red"))
            return self.begin()
        
        elif confirmation == 'n':
            print(colored("Cancelling...", "yellow"))
            return self.begin()
        
        elif confirmation == "exit":
            raise UserExits
        
        else:
            # for empty or invalid input
            return self.delete_db()


    def delete_all_data(self):
        confirmation = input("Are you sure you want to delete ALL data including user accounts? (Y/N) ")
        if confirmation.lower().strip() == 'y':
            payload = {
                "password": self.master_pw_,
                "user": self.user_
            }
            try:
                resp = requests.post(f"{SERVER_URL}/delete_all_data", json=payload, verify=SERVER_CERT)
                resp.raise_for_status()
                logging.critical(f"{self.user_} deleted ALL data including users on server")
                print(colored(f"✓ All data deleted successfully from server. {self.obj_.checkmark_}", "green"))
                self.salts.clear()
                sys.exit()
            except requests.HTTPError as e:
                print(colored(f"✗ Server delete all data failed: {e}", "red"))
                return self.begin()
            except Exception as e:
                print(colored(f"✗ Server delete all data failed: {e}", "red"))
                return self.begin()
        elif confirmation.lower().strip() == 'n':
            print(colored("Cancelling...", "red"))
            return self.begin()
        elif confirmation.lower().strip() == "exit":
            raise UserExits
        elif confirmation.strip() == "":
            return self.delete_all_data()

    def view_logs(self):
        print(colored("---- AUDIT LOGS ----", "yellow"))
        try:
            with open(LOGFILE, 'r') as f:
                lines = f.readlines()[-200:]  # show last 200 entries
                for ln in lines:
                    print(ln.strip())
        except FileNotFoundError:
            print(colored("No logs available.", "yellow"))
            
    def _server_encrypt(self, website, password):
        payload = {
            "password": self.master_pw_,
            "website": website,
            "data": password,
            "user": self.user_
        }
        try:
            resp = requests.post(f"{SERVER_URL}/encrypt", json=payload, verify=SERVER_CERT)
            resp.raise_for_status()
            salt = resp.json().get("salt")
            self.salts[website] = salt

            user_file = f"db/passwords_{self.user_}.json"
            enc_path = user_file + ".enc"
            dm = DataManip()
            if os.path.exists(enc_path):
                j = dm.decrypt_json(enc_path)
            else:
                j = {}
            # set salt (ensure website entry exists)
            if website not in j:
                j[website] = {}
            j[website]["salt"] = salt
            # persist via encrypt_json
            tmp_path = user_file
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(j, f, indent=4)
            dm.encrypt_json(tmp_path)

            print(colored(f"✓ Password for {website} stored securely on server.", "green"))
        except Exception as e:
            print(colored(f"✗ Server encrypt failed: {e}\n", "red"))

    def _server_decrypt(self, website):
        payload = {
            "user": self.user_,
            "website": website,
            "password": self.master_pw_
        }
        try:
            resp = requests.post(f"{SERVER_URL}/decrypt", json=payload, verify=SERVER_CERT, timeout=6)
            resp.raise_for_status()
            data = resp.json()
            decrypted = data.get("decrypted")
            if decrypted is None:
                print(colored(f"✗ Decrypt returned no data. Server response: {data}", "red"))
                return None
            return decrypted
        except requests.HTTPError as e:
            # show status + content for debugging
            try:
                content = resp.text
            except Exception:
                content = "<no body>"
            print(colored(f"✗ Server decrypt HTTP error: {e}\nResponse status: {resp.status_code}\nResponse content: {content}", "red"))
            return None
        except requests.RequestException as e:
            print(colored(f"✗ Server decrypt request failed: {e}", "red"))
            return None
        except Exception as e:
            print(colored(f"✗ Unexpected client error while decrypting: {e}", "red"))
            return None

    def _server_list_passwords(self):
        try:
            # include the user as query parameter
            resp = requests.get(f"{SERVER_URL}/list", params={"user": self.user_}, verify=SERVER_CERT)
            resp.raise_for_status()
            passwords = resp.json().get("stored_passwords", {})
            return passwords
        except requests.HTTPError as e:
            print(colored(f"✗ Server list passwords HTTP error: {e}", "red"))
            try:
                print("Response content:", resp.json())
            except Exception:
                pass
            return {}
        except Exception as e:
            print(colored(f"✗ Server list passwords failed: {e}", "red"))
            return {}

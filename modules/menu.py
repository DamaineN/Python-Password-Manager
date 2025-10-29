# modules/menu.py
import sys
import getpass
import pyperclip
import re
import threading
import time
import logging

from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import *

LOGFILE = "logs/activity.log"

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
    def __init__(self, obj: DataManip, filename: str, user: str, role: str, key_bytes: bytes):
        self.obj_ = obj
        self.filename_ = filename
        self.user_ = user
        self.role_ = role
        self.key_ = key_bytes

    def begin(self):
        try:
            choice = self.menu_prompt()
        except UserExits:
            raise UserExits

        if choice == '4': # User Exits
            raise UserExits

        if choice == '1': # add or update a password
            try:
                self.update_db()
                return self.begin()
            except UserExits:
                raise UserExits

        elif choice == '2': # look up a stored password
            try:
                string = self.load_password()
                website = string.split(':')[0]
                password = string.split(':')[1]
                print(colored(f"Password for {website}: {password}", "yellow"))

                copy_to_clipboard = input("Copy password to clipboard? (Y/N): ").strip()
                if copy_to_clipboard == "exit":
                    raise UserExits
                elif copy_to_clipboard.lower() == 'y':
                    try:
                        pyperclip.copy(password)
                        logging.info(f"{self.user_} copied password for {website}")
                        # spawn thread to clear clipboard
                        threading.Thread(target=self._clear_clipboard_later, daemon=True).start()
                        print(colored(f"{self.obj_.checkmark_} Password copied to clipboard (will clear after 30s)", "green"))
                    except pyperclip.PyperclipException:
                        print(colored(f"{self.obj_.x_mark_} Clipboard not available. {self.obj_.x_mark_}", "red"))
                return self.begin()
            except UserExits:
                raise UserExits
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}", "red"))
                return self.begin()

        elif choice == '3': # Delete a single password
            try:
                return self.delete_password()
            except UserExits:
                raise UserExits

        elif choice == '5': # Delete DB of Passwords
            if self.role_ != 'admin':
                print(colored("Permission denied: Admin only.", "red"))
                return self.begin()
            try:
                self.delete_db()
            except MasterPasswordIncorrect:
                print(colored(f"{self.obj_.x_mark_} Master password is incorrect {self.obj_.x_mark_}", "red"))
                return self.begin()
            except UserExits:
                raise UserExits

        elif choice == '6': # delete ALL data (admin)
            if self.role_ != 'admin':
                print(colored("Permission denied: Admin only.", "red"))
                return self.begin()
            try:
                self.delete_all_data()
            except MasterPasswordIncorrect:
                print(colored(f"{self.obj_.x_mark_} Master password is incorrect {self.obj_.x_mark_}", "red"))
                return self.begin()
            except UserExits:
                raise UserExits

        elif choice == '7': # admin: view logs
            if self.role_ != 'admin':
                print(colored("Permission denied: Admin only.", "red"))
                return self.begin()
            self.view_logs()
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

    def update_db(self):
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            pass
        except PasswordFileDoesNotExist:
            print(colored(f"--There are no passwords stored.--", "yellow"))

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
                    self.obj_.encrypt_data(self.filename_, password, self.key_, website)
                    logging.info(f"{self.user_} stored/updated password for {website}")
            elif gen_question.lower().strip() == 'y':
                password = self.__return_generated_password(website)
                self.obj_.encrypt_data(self.filename_, password, self.key_, website)
                logging.info(f"{self.user_} generated and stored password for {website}")

    def load_password(self):
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()

        website = input("Enter website for the password you want to retrieve: ").strip()
        if website.lower().strip() == "exit":
            raise UserExits
        elif website.strip() == "":
            return self.load_password()
        else:
            try:
                plaintext = self.obj_.decrypt_data(self.key_, website, self.filename_)
            except PasswordNotFound:
                print(colored(f"{self.obj_.x_mark_} Password for {website} not found {self.obj_.x_mark_}", "red"))
                return self.load_password()
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}", "red"))
                return self.begin()

            final_str = f"{website}:{plaintext}"
            logging.info(f"{self.user_} retrieved password for {website}")
            return final_str

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
        try:
            self.list_passwords()
        except PasswordFileIsEmpty:
            return self.begin()

        website = input("What website do you want to delete? (ex. google.com): ").strip()
        if website == "exit":
            raise UserExits
        elif website == "":
            return self.delete_password()
        else:
            try:
                self.obj_.delete_password(self.filename_, website)
                logging.warning(f"{self.user_} deleted password for {website}")
                print(colored(f"{self.obj_.checkmark_} Data for {website} deleted successfully.", "green"))
                return self.begin()
            except PasswordNotFound:
                print(colored(f"{self.obj_.x_mark_} {website} not in DB {self.obj_.x_mark_}", "red"))
                return self.delete_password()
            except PasswordFileDoesNotExist:
                print(colored(f"{self.obj_.x_mark_} DB not found. Try adding a password {self.obj_.x_mark_}", "red"))
                return self.begin()

    def delete_all_data(self):
        confirmation = input("Are you sure you want to delete all data? (Y/N) ")
        if confirmation.lower().strip() == 'y':
            try:
                self.obj_.delete_all_data(self.filename_, "db/users.json")
                logging.critical(f"{self.user_} deleted ALL data including user accounts")
                print(colored(f"{self.obj_.checkmark_} All Data Deleted successfully. {self.obj_.checkmark_}", "green"))
                sys.exit()
            except Exception:
                print(colored(f"{self.obj_.x_mark_} Error deleting all data {self.obj_.x_mark_}", "red"))
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

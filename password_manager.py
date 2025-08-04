import json
import os
import getpass
import base64
import secrets
import string
from cryptography.fernet import Fernet
from hashlib import sha256

FILE_NAME = "passwords.json"
passwords = {}

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def get_key_from_master(master_password):
    hash = sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(hash)

def encrypt_password(password, fernet):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, fernet):
    return fernet.decrypt(encrypted_password.encode()).decode()

def load_passwords(fernet):
    global passwords
    if os.path.exists(FILE_NAME):
        with open(FILE_NAME, "r") as file:
            try:
                raw = json.load(file)
                for site, creds in raw.items():
                    decrypy_password = decrypy_password(creds["password"], fernet)
                    passwords[site] = {
                        "username": creds["username"],
                        "password": decrypy_password
                    }
            except Exception as e:
                print("Error loading passwords:", e)
            
def save_passwords(fernet):
    encrypted_data = {}
    for site, creds in passwords.items():
        encrypted_data[site] = {
            "username": creds["username"],
            "password": encrypt_password(creds["password"], fernet)
        }
    with open(FILE_NAME, "w") as file:
        json.dump(encrypted_data, file, indent=4)

def add_password():
    site = input("Website name: ").strip().lower()
    username = input("Username: ").strip()
    
    choice = input("Do you want to generate a strong random password? (y/n): ").lower()
    if choice == "y":
        password = generate_password()
        print("Generated password:", password)
    else:
        password = getpass.getpass("Enter password: ").strip()

    passwords[site] = {
        "username": username,
        "password": password
    }
    save_passwords(fernet)
    print("Password saved.")

def list_sites():
    if not passwords:
        print("No saved passwords.")
        return
    print("Saved websites: ")
    for site in passwords:
        print("-", site)

def retrieve_password():
    site = input("Enter website name to retrieve: ").strip().lower()
    if site in passwords:
        print("Username:", passwords[site]["username"])
        print("Password:", passwords[site]["password"])
    else:
        print("No password saved for this site.")

print("Welcome to Secure Password Manager")
master_password = getpass.getpass("Enter your master password: ")
fernet = Fernet(get_key_from_master(master_password))

load_passwords(fernet)

while True:
    print("\n== PASSWORD MANAGER ===")
    print("1 - Add new password")
    print("2 - List saved websites")
    print("3 - Retrieve password for a website")
    print("4 - Exit")

    choice = input("Your choice: ")

    if choice == "1":
        add_password()
    elif choice == "2":
        list_sites()
    elif choice == "3":
        retrieve_password()
    elif choice == "4":
        print("Exiting...")
        break
    else:
        print("Invalid choice!")
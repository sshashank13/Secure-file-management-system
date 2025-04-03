import os
import hashlib
import base64
import json
import pyotp
import time
import shutil
from cryptography.fernet import Fernet
from getpass import getpass
from datetime import datetime

# Generate encryption key (Use Google Authenticator)
KEY_FILE = "key.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as key_file:
        key = Fernet.generate_key()
        key_file.write(key)
else:
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
fernet = Fernet(key)

# User database (for demonstration purposes) 
USER_DB = "users.json"
if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump({}, f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_otp_secret():
    return pyotp.random_base32()

def reset_account(username):
    with open(USER_DB, "r") as f:
        users = json.load(f)
    
    if username in users:
        del users[username]
        with open(USER_DB, "w") as f:
            json.dump(users, f)
        print("Account reset successful. Please register again.")
    else:
        print("User not found!")

def register():
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    hashed_password = hash_password(password)
    otp_secret = generate_otp_secret()
    
    with open(USER_DB, "r") as f:
        users = json.load(f)
    
    if username in users:
        print("User already exists!")
        return
    
    users[username] = {"password": hashed_password, "otp_secret": otp_secret, "files": {}}
    with open(USER_DB, "w") as f:
        json.dump(users, f)
    print("User registered successfully! Use Google Authenticator with the secret key:", otp_secret)

def verify_otp(secret):
    otp = input("Enter OTP: ")
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

def login():
    username = input("Enter username: ")
    password = getpass("Enter password: ")
    
    with open(USER_DB, "r") as f:
        users = json.load(f)
    
    if username not in users or users[username].get("password") != hash_password(password):
        print("Invalid credentials!")
        return None
    
    if "otp_secret" not in users[username]:
        print("OTP Secret missing! Resetting account...")
        reset_account(username)
        return None
    
    if not verify_otp(users[username]["otp_secret"]):
        print("Invalid OTP!")
        return None
    
    print("Login successful!")
    return username

def encrypt_file(file_path):
    with open(file_path, "rb") as file:
        encrypted_data = fernet.encrypt(file.read())
    with open(file_path, "wb") as file:
        file.write(encrypted_data)
    print("File encrypted successfully!")

def decrypt_file(file_path):
    with open(file_path, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    with open(file_path, "wb") as file:
        file.write(decrypted_data)
    print("File decrypted successfully!")

def save_file(username, file_path):
    encrypt_file(file_path)
    with open(USER_DB, "r") as f:
        users = json.load(f)
    users[username]["files"][file_path] = str(datetime.now())
    with open(USER_DB, "w") as f:
        json.dump(users, f)
    print("File stored securely!")

def delete_file(username, file_path):
    with open(USER_DB, "r") as f:
        users = json.load(f)
    
    if file_path in users[username]["files"]:
        os.remove(file_path)
        del users[username]["files"][file_path]
        with open(USER_DB, "w") as f:
            json.dump(users, f)
        print("File deleted successfully!")
    else:
        print("File not found in your storage!")

def detect_threats(file_path):
    if os.path.getsize(file_path) > 100000000:  # Example: Files larger than 100MB are flagged
        print("Warning: Large file detected, potential security risk!")
    if file_path.endswith((".exe", ".bat", ".sh")):
        print("Warning: Executable file detected, potential malware risk!")

def view_metadata(username, file_path):
    if not os.path.exists(file_path):
        print("File does not exist!")
        return
    
    with open(USER_DB, "r") as f:
        users = json.load(f)
    
    if file_path not in users[username]["files"]:
        print("File metadata not found!")
        return
    
    metadata = os.stat(file_path)
    print(f"File: {file_path}")
    print(f"Size: {metadata.st_size} bytes")
    print(f"Last Modified: {datetime.fromtimestamp(metadata.st_mtime)}")
    print(f"Created: {datetime.fromtimestamp(metadata.st_ctime)}")

def list_files(username):
    with open(USER_DB, "r") as f:
        users = json.load(f)
    files = users[username].get("files", {})
    for file, timestamp in files.items():
        print(f"{file} - Last modified: {timestamp}")

def main():
    while True:
        choice = input("1. Register\n2. Login\n3. Exit\nChoose an option: ")
        if choice == "1":
            register()
        elif choice == "2":
            user = login()
            if user:
                while True:
                    action = input("1. Upload File\n2. List Files\n3. Delete File\n4. View Metadata\n5. Logout\nChoose: ")
                    if action == "1":
                        file_path = input("Enter file path: ")
                        detect_threats(file_path)
                        save_file(user, file_path)
                    elif action == "2":
                        list_files(user)
                    elif action == "3":
                        file_path = input("Enter file path to delete: ")
                        delete_file(user, file_path)
                    elif action == "4":
                        file_path = input("Enter file path to view metadata: ")
                        view_metadata(user, file_path)
                    elif action == "5":
                        break
        elif choice == "3":
            break

if __name__ == "__main__":
    main()
    

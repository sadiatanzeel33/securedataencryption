import streamlit as st
import json
import time
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from passlib.hash import pbkdf2_sha256

# --- Configuration ---
DATA_FILE = "encrypted_data.json"
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION = 60  # seconds

user_data = {}
failed_login_attempts = {}

# --- Key Derivation ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_cipher(username, password):
    if username not in user_data:
        return None
    salt = base64.b64decode(user_data[username]["salt"])
    key = derive_key(password, salt)
    return Fernet(key)

# --- Data Load/Save ---
def load_data():
    global user_data
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    data = json.loads(content)
                    user_data = data.get("user_data", {})
                else:
                    user_data = {}
                    save_data()
        except (json.JSONDecodeError, IOError) as e:
            st.warning(f"⚠️ Error loading data: {e}")
            user_data = {}
            save_data()
    else:
        user_data = {}
        save_data()

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump({"user_data": user_data}, f, indent=4)

# --- Authentication & Lockout ---
def verify_master_password(username, password):
    return pbkdf2_sha256.verify(password, user_data[username]["hashed_master_pass"])

def check_lockout(username):
    if username in failed_login_attempts:
        if failed_login_attempts[username]["attempts"] >= MAX_FAILED_ATTEMPTS:
            time_since_last = time.time() - failed_login_attempts[username]["last_attempt"]
            if time_since_last < LOCKOUT_DURATION:
                st.error(f"🔒 Account locked. Try again in {int(LOCKOUT_DURATION - time_since_last)}s.")
                return True
            else:
                failed_login_attempts[username] = {"attempts": 0, "last_attempt": 0}
    return False

def update_failed_attempt(username):
    if username not in failed_login_attempts:
        failed_login_attempts[username] = {"attempts": 0, "last_attempt": 0}
    failed_login_attempts[username]["attempts"] += 1
    failed_login_attempts[username]["last_attempt"] = time.time()
    remaining = MAX_FAILED_ATTEMPTS - failed_login_attempts[username]["attempts"]
    st.error(f"❌ Incorrect password! Attempts remaining: {remaining}")
    if remaining <= 0:
        st.warning(f"🔒 Account {username} locked for {LOCKOUT_DURATION} seconds.")

# --- Encryption / Decryption ---
def encrypt_data(plain_text, cipher):
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text, cipher):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# --- Load data on start ---
load_data()

# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

if "current_user" not in st.session_state or st.session_state.current_user is None:
    st.subheader("🔑 Login or Register")
    new_user = st.checkbox("New User?")
    username = st.text_input("Username:")
    master_password = st.text_input("Master Password:", type="password")

    if st.button("Login/Register"):
        if not username or not master_password:
            st.error("⚠️ Username and Master Password are required.")
        elif check_lockout(username):
            pass
        elif new_user:
            if username in user_data:
                st.error("⚠️ Username already exists.")
            else:
                salt = os.urandom(16)
                salt_b64 = base64.b64encode(salt).decode()
                hashed_pw = pbkdf2_sha256.hash(master_password)
                user_data[username] = {
                    "salt": salt_b64,
                    "hashed_master_pass": hashed_pw,
                    "encrypted_data": {}
                }
                save_data()
                st.success(f"✅ Registered '{username}'. You can now log in.")
        else:
            if username in user_data and verify_master_password(username, master_password):
                st.session_state.current_user = username
                st.session_state.current_password = master_password
                st.success(f"✅ Logged in as {username}")
                st.experimental_rerun()
            else:
                update_failed_attempt(username)
else:
    username = st.session_state.current_user
    master_password = st.session_state.current_password
    st.sidebar.subheader(f"👤 {username}")
    if st.sidebar.button("Logout"):
        st.session_state.current_user = None
        st.session_state.current_password = None
        st.experimental_rerun()

    menu = ["Store Data", "Retrieve Data"]
    choice = st.sidebar.radio("Menu", menu)

    if choice == "Store Data":
        st.subheader("📂 Store Data")
        data_key = st.text_input("Data Identifier:")
        plain_text = st.text_area("Enter your data:")

        if st.button("Encrypt & Save"):
            if data_key and plain_text:
                cipher = get_cipher(username, master_password)
                encrypted = encrypt_data(plain_text, cipher)
                user_data[username]["encrypted_data"][data_key] = {
                    "encrypted_text": encrypted
                }
                save_data()
                st.success(f"✅ Data '{data_key}' saved securely.")
            else:
                st.error("⚠️ Both fields are required.")

    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Data")
        stored_keys = list(user_data[username]["encrypted_data"].keys())
        if not stored_keys:
            st.info("No data stored yet.")
        else:
            selected_key = st.selectbox("Choose data:", stored_keys)
            confirm_pw = st.text_input("Re-enter Master Password:", type="password")

            if st.button("Decrypt & Retrieve"):
                if confirm_pw:
                    if verify_master_password(username, confirm_pw):
                        cipher = get_cipher(username, confirm_pw)
                        encrypted = user_data[username]["encrypted_data"][selected_key]["encrypted_text"]
                        decrypted = decrypt_data(encrypted, cipher)
                        if decrypted:
                            st.success(f"✅ Decrypted Data ({selected_key}):")
                            st.code(decrypted)
                        else:
                            st.error("❌ Decryption failed.")
                    else:
                        st.error("❌ Incorrect Master Password.")
                else:
                    st.error("⚠️ Password required.")

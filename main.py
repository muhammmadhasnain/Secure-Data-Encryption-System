import streamlit as st # type: ignore
import json
import os
import time
from cryptography.fernet import Fernet # type: ignore
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
lOCKOUT_DURATION = 60

if "authication_user" not in st.session_state:
    st.session_state.authication_user = None

if "failed_attemps" not in st.session_state:
    st.session_state.failed_attemps = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE , "r") as f:
           return json.load(f)
        
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000, dklen=32)
    return urlsafe_b64encode(key)


def hash_password(password):
    return pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(encrypt_data, key):
    cipher = Fernet(generate_key(key))
    encrypted =   cipher.encrypt(encrypt_data.encode())
    return encrypted.decode()

def decrypt_text(decrypt_data, key):
    try:
        cipher = Fernet(generate_key(key))
        decrypted = cipher.decrypt(decrypt_data.encode())
        return  decrypted.decode( )
    except:
        None
          
    
stored_data = load_data()


st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]

choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("""
    ### 🔐 Secure Data Storage and Retrieval System

    - Users store data with a unique passkey.  
    - Users decrypt data by providing the correct passkey.  
    - Multiple failed attempts result in a forced reauthorization (login page).  
    - The system operates entirely in memory without external databases.  
    """)
elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("choose username")
    password = st.text_input("choose password", type="password")
    

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("User already exits")
            else:
                stored_data[username] = {
                    "password" : hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User register successfuly")
        else:
            st.error("⚠️ Both field are required")

elif choice == "Login":
    st.subheader("User Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too mainy failed attempts. please wait {remaining} seconds. ")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authication_user = username
            st.session_state.failed_attemps = 0
            st.success(f" Welcome {username}")

        else: 
            st.session_state.failed_attemps += 1
            max_attemps = 3
            remaining =  max_attemps - st.session_state.failed_attemps
            st.error(f"Invalied credentials! Attemps left: {remaining}")

            if st.session_state.failed_attemps >= 3:
                st.session_state.lockout_time = time.time() + lOCKOUT_DURATION
                st.error(f"⚠️ To many failed attemps. Locked for 60 attemps")
                st.stop()

elif choice == "Store Data":
     st.subheader("📂 Store Data Securely")
     data = st.text_area("Enter data to encrty")
     passkey = st.text_input("Encryption key (passphrase)", type= "password")


     if st.button("Encryt and save"):
         if data and passkey:
            encryt = encrypt_text(data , passkey)
            stored_data[st.session_state.authication_user]["data"].append(encryt)
            save_data(stored_data)
            st.success("✅ Data encryted and save successfully!")

         else:
             st.error("⚠️ All fields are requied to fill")
         
            

elif choice == "Retrieve Data":
    if not st.session_state.authication_user:
        st.warning("Please login first")

    else:
        st.subheader("🔑 Reauthorization Required")
        user_data = stored_data.get(st.session_state.authication_user, {}).get("data", [])

        if not user_data:
            st.info("No Data found")
        
        else:
            st.write("Encryted data entries")
            for i , item in enumerate(user_data):
                st.code(item, language="text") 
            
            encrypt_input = st.text_area("Enter encrypted text")
            passkey = st.text_input("Enter passkey T Decrypt", type= "password")
            
            if st.button("decrpt"):
                if encrypt_input and passkey:
                    result = decrypt_text(encrypt_input , passkey)
                    if result:
                        st.success(f"✅ Decrypted {result}")
                    else:
                        st.error("❌ Incorred passkey")

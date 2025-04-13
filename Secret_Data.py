import streamlit as st
from cryptography.fernet import Fernet
import base64
import os

# --- Method 1: Fernet ---
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_fernet(message):
    key = load_key()
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    with open("encrypted.txt", "wb") as file:
        file.write(encrypted)
    return encrypted

def decrypt_fernet():
    key = load_key()
    f = Fernet(key)
    with open("encrypted.txt", "rb") as file:
        encrypted = file.read()
    return f.decrypt(encrypted).decode()


# --- Method 2: Base64 ---
def encrypt_base64(message):
    return base64.b64encode(message.encode()).decode()

def decrypt_base64(encoded):
    return base64.b64decode(encoded.encode()).decode()


# --- Method 3: Caesar Cipher ---
def encrypt_caesar(message, shift=3):
    result = ""
    for char in message:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def decrypt_caesar(message, shift=3):
    return encrypt_caesar(message, -shift)


# --- Streamlit UI ---
st.title("🔐 Multi-Method Encryptor App")

menu = st.sidebar.selectbox("Select Option", ["Generate Key (Fernet)", "Encrypt Message", "Decrypt Message"])
method = st.sidebar.selectbox("Choose Method", ["Fernet", "Base64", "Caesar Cipher"])

# Generate Key (Fernet only)
if menu == "Generate Key (Fernet)":
    if st.button("Generate Secret Key"):
        generate_key()
        st.success("🔑 Secret Key Generated and saved as 'secret.key'.")

# Encryption Section
elif menu == "Encrypt Message":
    message = st.text_area("🔒 Enter message to encrypt:")
    if st.button("Encrypt"):
        if method == "Fernet":
            if not os.path.exists("secret.key"):
                st.warning("⚠️ Please generate the Fernet key first.")
            else:
                encrypted = encrypt_fernet(message)
                st.success("✅ Message Encrypted with Fernet.")
                st.code(encrypted.decode())
        elif method == "Base64":
            encoded = encrypt_base64(message)
            st.success("✅ Message Encoded with Base64.")
            st.code(encoded)
        elif method == "Caesar Cipher":
            encrypted = encrypt_caesar(message)
            st.success("✅ Message Encrypted with Caesar Cipher.")
            st.code(encrypted)

# Decryption Section
elif menu == "Decrypt Message":
    if method == "Fernet":
        if not os.path.exists("secret.key") or not os.path.exists("encrypted.txt"):
            st.warning("⚠️ Fernet key or encrypted file missing.")
        else:
            try:
                decrypted = decrypt_fernet()
                st.success("🔓 Decrypted with Fernet:")
                st.code(decrypted)
            except Exception as e:
                st.error(f"❌ Decryption failed: {str(e)}")
    elif method == "Base64":
        encoded = st.text_input("Paste Base64 encoded message:")
        if st.button("Decrypt"):
            try:
                decoded = decrypt_base64(encoded)
                st.success("🔓 Decoded Base64 message:")
                st.code(decoded)
            except Exception as e:
                st.error("❌ Invalid Base64 string")
    elif method == "Caesar Cipher":
        encrypted = st.text_input("Enter Caesar Cipher message:")
        if st.button("Decrypt"):
            decrypted = decrypt_caesar(encrypted)
            st.success("🔓 Decrypted Caesar Cipher message:")
            st.code(decrypted)

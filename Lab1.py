# cia_triad_streamlit.py
# Streamlit app demonstrating CIA Triad: Confidentiality, Integrity, Availability

import streamlit as st
import hashlib
import random
import time
from cryptography.fernet import Fernet

st.title("CIA Triad Simulation")

# ------------------ Confidentiality ------------------
st.header("1️⃣ Confidentiality")

# User input
user_message = st.text_input("Enter a secret message to encrypt:")

if user_message:
    data = user_message.encode()

    # Generate secret key
    key = Fernet.generate_key()
    cipher = Fernet(key)

    # Encrypt
    encrypted = cipher.encrypt(data)
    st.success(f"Encrypted data: {encrypted}")

    # Decrypt
    decrypted = cipher.decrypt(encrypted)
    st.info(f"Decrypted data (authorized): {decrypted}")

    # Unauthorized access attempt
    fake_key = Fernet(Fernet.generate_key())
    try:
        fake_key.decrypt(encrypted)
    except Exception as e:
        st.warning(f"Unauthorized access blocked: {e}")

# ------------------ Integrity ------------------
st.header("2️⃣ Integrity")

if user_message:
    # Compute original hash
    original_hash = hashlib.sha256(data).hexdigest()
    st.success(f"Original hash: {original_hash}")

    # Tamper option
    tamper = st.checkbox("Simulate data tampering?")
    if tamper:
        tampered_data = data[:-1] + b"x"  # simple tampering
    else:
        tampered_data = data

    tampered_hash = hashlib.sha256(tampered_data).hexdigest()
    st.info(f"Tampered hash: {tampered_hash}")

    if original_hash == tampered_hash:
        st.success("Data integrity verified ✅")
    else:
        st.error("Data integrity compromised ❌")

# ------------------ Availability ------------------
st.header("3️⃣ Availability")

def access_service():
    """Simulate a service that randomly fails"""
    if random.random() < 0.3:
        raise Exception("Server down!")
    return "Service data retrieved successfully"

attempts = st.slider("Number of service access attempts:", 1, 10, 5)
if st.button("Simulate Service Access"):
    for attempt in range(1, attempts + 1):
        try:
            result = access_service()
            st.success(f"Attempt {attempt}: Success -> {result}")
        except Exception as e:
            st.error(f"Attempt {attempt}: Failed -> {e}")
            time.sleep(0.5)

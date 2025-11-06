import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import jwt, datetime

# =========================================================
# Digital Signature Functions (from 8_a_.py)
# =========================================================
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def generate_signature(message: str):
    message_bytes = message.encode()
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), 
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message: str, signature: bytes):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# =========================================================
# JWT Authentication Functions (from 8_b_.py)
# =========================================================
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
users = {"admin": "12345"}

def create_jwt(username: str):
    token = jwt.encode(
        {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return token

def verify_jwt(token: str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        return "Expired"
    except jwt.InvalidTokenError:
        return "Invalid"

# =========================================================
# Tkinter GUI
# =========================================================
root = tk.Tk()
root.title("Digital Signature & JWT Authentication")
root.geometry("600x400")

tabControl = ttk.Notebook(root)

# -------------------------
# Digital Signature Tab
# -------------------------
tab1 = ttk.Frame(tabControl)
tabControl.add(tab1, text="Digital Signature")

msg_label = tk.Label(tab1, text="Enter Message:")
msg_label.pack(pady=5)
msg_entry = tk.Entry(tab1, width=50)
msg_entry.pack(pady=5)

sig_text = tk.Text(tab1, height=5, width=70)
sig_text.pack(pady=5)

def sign_message():
    message = msg_entry.get()
    if not message:
        messagebox.showerror("Error", "Enter a message")
        return
    signature = generate_signature(message)
    sig_text.delete(1.0, tk.END)
    sig_text.insert(tk.END, signature.hex())
    messagebox.showinfo("Success", "Signature generated!")

def verify_message():
    message = msg_entry.get()
    signature_hex = sig_text.get(1.0, tk.END).strip()
    try:
        signature = bytes.fromhex(signature_hex)
        if verify_signature(message, signature):
            messagebox.showinfo("Result", "Signature is VALID ✅")
        else:
            messagebox.showerror("Result", "Signature is INVALID ❌")
    except Exception:
        messagebox.showerror("Error", "Invalid signature format")

tk.Button(tab1, text="Generate Signature", command=sign_message).pack(pady=5)
tk.Button(tab1, text="Verify Signature", command=verify_message).pack(pady=5)

# -------------------------
# JWT Authentication Tab
# -------------------------
tab2 = ttk.Frame(tabControl)
tabControl.add(tab2, text="JWT Authentication")

user_label = tk.Label(tab2, text="Username:")
user_label.pack(pady=5)
user_entry = tk.Entry(tab2, width=30)
user_entry.pack(pady=5)

pass_label = tk.Label(tab2, text="Password:")
pass_label.pack(pady=5)
pass_entry = tk.Entry(tab2, width=30, show="*")
pass_entry.pack(pady=5)

token_text = tk.Text(tab2, height=5, width=70)
token_text.pack(pady=5)

def login_user():
    username = user_entry.get()
    password = pass_entry.get()
    if username in users and users[username] == password:
        token = create_jwt(username)
        token_text.delete(1.0, tk.END)
        token_text.insert(tk.END, token)
        messagebox.showinfo("Login Success", f"JWT Token generated for {username}")
    else:
        messagebox.showerror("Error", "Invalid credentials")

def check_token():
    token = token_text.get(1.0, tk.END).strip()
    result = verify_jwt(token)
    if result == "Expired":
        messagebox.showerror("Result", "Token Expired ⏳")
    elif result == "Invalid":
        messagebox.showerror("Result", "Token Invalid ❌")
    else:
        messagebox.showinfo("Result", f"Token is valid ✅\nHello {result['user']}!")

tk.Button(tab2, text="Login & Get Token", command=login_user).pack(pady=5)
tk.Button(tab2, text="Verify Token", command=check_token).pack(pady=5)

# -------------------------
tabControl.pack(expand=1, fill="both")

root.mainloop()

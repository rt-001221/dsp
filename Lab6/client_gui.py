import socket, ssl, threading, tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pickle

HOST = "127.0.0.1"
PORT = 12345

# Custom popup for name input
class NameDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Enter Your Name")
        self.geometry("400x150")  # Bigger popup
        self.resizable(False, False)
        self.name = None

        tk.Label(self, text="Enter your name:", font=("Arial", 14)).pack(pady=(20,10))

        self.entry = tk.Entry(self, font=("Arial", 14), width=30)
        self.entry.pack(pady=10)
        self.entry.focus_set()

        tk.Button(self, text="OK", font=("Arial", 12), command=self.on_ok).pack(pady=10)

        self.bind("<Return>", lambda e: self.on_ok())

    def on_ok(self):
        self.name = self.entry.get().strip()
        if not self.name:
            self.name = "Anonymous"
        self.destroy()

# Main client GUI
class SecureClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("🔐 Secure E2EE Chat Client")

        # RSA keypair
        self.rsa_key = RSA.generate(2048)
        self.cipher_rsa = PKCS1_OAEP.new(self.rsa_key)

        # GUI layout
        self.chat_area = scrolledtext.ScrolledText(
            master, wrap=tk.WORD, state="disabled", width=70, height=30, font=("Arial", 12)
        )
        self.chat_area.pack(padx=10, pady=10)

        self.entry = tk.Entry(master, width=60, font=("Arial", 12))
        self.entry.pack(side=tk.LEFT, padx=(10,0), pady=(0,10))
        self.entry.bind("<Return>", lambda e: self.send_message())

        self.send_button = tk.Button(master, text="Send", command=self.send_message, font=("Arial", 12))
        self.send_button.pack(side=tk.LEFT, padx=(5,10), pady=(0,10))

        # Show custom name dialog
        dialog = NameDialog(master)
        master.wait_window(dialog)
        self.name = dialog.name

        # Other clients public keys
        self.peers_keys = {}  # addr string -> RSA key object

        # Connect to server
        self.connect_to_server()

    def connect_to_server(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = context.wrap_socket(raw_sock, server_hostname="localhost")
        try:
            self.conn.connect((HOST, PORT))
            self.add_message("🟢 Connected to server.")

            # Send own public key
            self.conn.send(self.rsa_key.publickey().export_key())

            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.add_message(f"❌ Connection failed: {e}")

    def add_message(self, msg):
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state="disabled")

    def send_message(self):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)

        # Encrypt for all known peers
        for peer_addr, pub_key in self.peers_keys.items():
            cipher = PKCS1_OAEP.new(pub_key)
            encrypted_msg = cipher.encrypt(f"{self.name}: {msg}".encode())
            try:
                self.conn.send(encrypted_msg)
            except Exception as e:
                self.add_message(f"⚠️ Send failed: {e}")
        self.add_message(f"You: {msg}")

    def receive_messages(self):
        while True:
            try:
                data = self.conn.recv(8192)
                if not data:
                    break
                # Try to unpickle -> if keys dictionary
                try:
                    keys_dict = pickle.loads(data)
                    self.peers_keys = {addr: RSA.import_key(key) for addr, key in keys_dict.items() if addr != str(self.conn.getsockname())}
                    continue
                except:
                    pass
                # Try to decrypt with own private key
                try:
                    decrypted = self.cipher_rsa.decrypt(data).decode()
                    self.add_message(f"{decrypted}")
                except:
                    pass  # Ignore messages not meant for this client
            except Exception as e:
                self.add_message(f"⚠️ Receive error: {e}")
                break
        self.conn.close()

if __name__ == "__main__":
    root = tk.Tk()
    client = SecureClientGUI(root)
    root.mainloop()

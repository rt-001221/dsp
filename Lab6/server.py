import socket, ssl, threading, os
import pickle

HOST = "127.0.0.1"
PORT = 12345
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

class SecureServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.clients = []       # list of (conn, addr)
        self.client_keys = {}   # addr -> public key bytes

    def start(self):
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            print("❌ server.crt or server.key missing.")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

        bindsocket = socket.socket()
        bindsocket.bind((self.host, self.port))
        bindsocket.listen(5)
        print(f"🔒 Secure Server listening on {self.host}:{self.port}")

        while True:
            client_sock, addr = bindsocket.accept()
            conn = context.wrap_socket(client_sock, server_side=True)
            self.clients.append((conn, addr))
            print(f"✅ Client connected: {addr}")
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn, addr):
        try:
            # Receive client public key
            client_pubkey = conn.recv(4096)
            self.client_keys[addr] = client_pubkey

            # Broadcast updated keys to all clients
            self.broadcast_keys()

            while True:
                data = conn.recv(8192)
                if not data:
                    break
                # Relay message to all clients except sender
                for c, a in self.clients:
                    if a != addr:
                        try:
                            c.send(data)
                        except:
                            pass
        except Exception as e:
            print(f"⚠️ Error with {addr}: {e}")
        finally:
            if (conn, addr) in self.clients:
                self.clients.remove((conn, addr))
            if addr in self.client_keys:
                del self.client_keys[addr]
            conn.close()
            self.broadcast_keys()

    def broadcast_keys(self):
        keys_dict = {str(addr): key for addr, key in self.client_keys.items()}
        keys_bytes = pickle.dumps(keys_dict)
        for conn, addr in self.clients:
            try:
                conn.send(keys_bytes)
            except:
                pass

if __name__ == "__main__":
    server = SecureServer()
    server.start()

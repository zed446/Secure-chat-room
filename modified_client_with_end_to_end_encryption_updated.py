
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt the dynamic AES key with the RSA public key
def encrypt_aes_key_with_rsa(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return base64.b64encode(encrypted_aes_key)

# Generate a new AES key for each session
def generate_aes_key():
    return get_random_bytes(16)  # AES key of length 16 bytes

import tkinter as tk
from tkinter import scrolledtext
import socket
import ssl

from Crypto.Cipher import AES
import base64
import os
import threading


# AES encryption/decryption setup
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw, key, iv):
    raw = pad(raw)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode()))

def decrypt(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:])).decode('utf-8')

# Assuming symmetric key and IV are predefined and securely shared
symmetric_key = b'1234567890abcdef'  # Example 16-byte key
iv = os.urandom(16)  # This will generate a random 16-byte IV
def receive_messages(secure_socket, text_area):
    while True:
        try:
            
            encrypted_message = secure_socket.recv(1024)
            message = decrypt(encrypted_message, symmetric_key)

            text_area.config(state=tk.NORMAL)
            text_area.insert(tk.END, message + "\n")
            text_area.config(state=tk.DISABLED)
        except Exception as e:
            print(e)
            break

def send_message(secure_socket, message_entry, text_area):
    message = message_entry.get()
    
    encrypted_message = encrypt(message, symmetric_key, iv)
    secure_socket.send(encrypted_message)

    message_entry.delete(0, tk.END)
    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, "You: " + message + "\n")
    text_area.config(state=tk.DISABLED)

def create_ssl_context():
    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations('selfsigned.crt')  # Replace with your certificate path
    return ssl_context

def connect_to_server(ssl_context, host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_socket = ssl_context.wrap_socket(server_socket, server_hostname=host)
    secure_socket.connect((host, port))
    return secure_socket

def create_ssl_context():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


root = tk.Tk()
root.title("Secure chat Room")

text_area = scrolledtext.ScrolledText(root, state=tk.DISABLED, height=15)
text_area.pack(padx=20, pady=5)

message_entry = tk.Entry(root, width=50)
message_entry.pack(side=tk.LEFT, padx=20, pady=5)

send_button = tk.Button(root, text="Send", command=lambda: send_message(secure_socket, message_entry, text_area))
send_button.pack(side=tk.RIGHT, padx=20, pady=5)

if __name__ == '__main__':
    ssl_context = create_ssl_context()
    secure_socket = connect_to_server(ssl_context, '127.0.0.1', 8080)  # Updated server address and port
    threading.Thread(target=receive_messages, args=(secure_socket, text_area), daemon=True).start()
    root.mainloop()

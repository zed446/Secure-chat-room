
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Decrypt the AES key with the RSA private key
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = rsa_cipher.decrypt(base64.b64decode(encrypted_aes_key))
    return decrypted_aes_key

import socket
import ssl
import select
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)

# List of socket objects for currently connected clients
connected_clients_sockets = []

# Call this function wherever you detect a client has disconnected

def handle_client_disconnection(client_socket, connected_clients_sockets):
    try:
        connected_clients_sockets.remove(client_socket)
    except ValueError:
        pass  # Socket was not in the list
    finally:
        client_socket.close()

def broadcast_to_clients(sender_socket, message, connected_clients_sockets):
    for client_socket in connected_clients_sockets[:]:  # Make a copy of the list
        if client_socket != sender_socket:
            # Set the socket to non-blocking
            client_socket.setblocking(0)
            
            try:
                # Check if we can write to the socket
                ready_to_write, _, _ = select.select([], [client_socket], [], 0)
                if ready_to_write:
                    client_socket.send(message)
            except Exception as e:
                # If an error occurs, log it, close the socket, and remove it from the list
                logging.error(f'Error broadcasting message: {e}')
                client_socket.close()
                if client_socket in connected_clients_sockets:
                    connected_clients_sockets.remove(client_socket)

    for client_socket in connected_clients_sockets:
        # Send to all clients except the sender
        if client_socket != sender_socket:
            try:
                client_socket.send(message)
            except Exception as e:
                logging.error(f'Error broadcasting message: {e}')
                client_socket.close()
                connected_clients_sockets.remove(client_socket)

def main():
    host = '127.0.0.1'
    port = 8080
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Setup the SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='selfsigned.crt', keyfile='private.key')
    
    # Bind and start listening
    server_socket.bind((host, port))
    server_socket.listen(5)
    logging.info(f'Server listening on {host}:{port}')

    # Add server socket to the list of readable connections
    connected_clients_sockets.append(server_socket)

    try:
        while True:
            # Get the list sockets which are ready to be read through select
            r_socks, _, _ = select.select(connected_clients_sockets, [], [])
            for sock in r_socks:
                # New connection
                if sock == server_socket:
                    client_socket, addr = server_socket.accept()
                    secure_client_socket = context.wrap_socket(client_socket, server_side=True)
                    connected_clients_sockets.append(secure_client_socket)
                    logging.info(f'Connection established with {addr}')
                # Existing connection with a client sending a message
                else:
                    try:
                        data = sock.recv(1024)
                        if data:
                            # Broadcast message to other clients
                            broadcast_to_clients(sock, data, connected_clients_sockets)
                    except Exception as e:
                        logging.error(f'Error handling client data: {e}')
                        sock.close()
                        connected_clients_sockets.remove(sock)
    except Exception as e:
        logging.error(f'Server error: {e}')
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()

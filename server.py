import socket
import threading
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64


class WPA3Server:
    def __init__(self):
        # Generate ECDH key pair for the server
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.anonce = os.urandom(32)  # Generate random nonce
        self.snonce = None
        self.session_key = None

    def derive_session_key(self, peer_public_key, anonce, snonce):
        """Derive the session key using ECDH and HKDF"""
        # Perform ECDH key exchange
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        # Use HKDF to derive the session key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=anonce + snonce
        )
        self.session_key = hkdf.derive(shared_secret)
        return self.session_key

    def encrypt_message(self, message):
        """Encrypt a message using AES-GCM with the session key"""
        if not self.session_key:
            raise Exception("Session key not established")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv))
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt_message(self, encrypted_message):
        """Decrypt a message using AES-GCM with the session key"""
        if not self.session_key:
            raise Exception("Session key not established")

        decoded = base64.b64decode(encrypted_message.encode())
        iv = decoded[:16]
        tag = decoded[16:32]
        ciphertext = decoded[32:]

        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext).decode() + decryptor.finalize().decode()


def handle_client(client_socket, addr, wpa3_server):
    """Handle individual client connections"""
    try:
        print(f"[*] Accepted connection from {addr}")

        # Step 1: Send ANonce and public key
        public_bytes = wpa3_server.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(wpa3_server.anonce + public_bytes)
        print("[*] Sent ANonce and public key")

        # Step 2: Receive SNonce and client public key
        data = client_socket.recv(4096)
        wpa3_server.snonce = data[:32]
        client_public_key = serialization.load_pem_public_key(data[32:])
        print("[*] Received SNonce and client public key")

        # Step 3: Derive session key
        session_key = wpa3_server.derive_session_key(
            client_public_key,
            wpa3_server.anonce,
            wpa3_server.snonce
        )
        print(f"[*] SESSION KEY (hex): {session_key.hex()}")

        # Step 4: Test encrypted communication
        encrypted = wpa3_server.encrypt_message("Secure connection established from AP!")
        client_socket.send(encrypted.encode())
        print(f"[*] Sent encrypted packet: {encrypted}")

        # Receive encrypted response
        encrypted_response = client_socket.recv(4096).decode()
        decrypted = wpa3_server.decrypt_message(encrypted_response)
        print(f"[*] Received encrypted packet: {encrypted_response}")
        print(f"[*] Decrypted packet: {decrypted}")

        # Continue with secure communication
        while True:
            encrypted_msg = client_socket.recv(4096).decode()
            if not encrypted_msg:
                break

            # Decrypt incoming packet
            decrypted_msg = wpa3_server.decrypt_message(encrypted_msg)
            print(f"\n[CLIENT] Received encrypted packet: {encrypted_msg}")
            print(f"[CLIENT] Decrypted message: {decrypted_msg}")

            # Echo back encrypted response
            response = f"Server received: {decrypted_msg}"
            encrypted_response = wpa3_server.encrypt_message(response)
            client_socket.send(encrypted_response.encode())
            print(f"[SERVER] Sent encrypted packet: {encrypted_response}")
            print(f"[SERVER] Original message: {response}")

    except Exception as e:
        print(f"[!] Error handling client: {e}")
    finally:
        client_socket.close()
        print(f"[*] Connection closed with {addr}")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 12345))
    server.listen(5)
    print("[*] WPA3 AP listening on 0.0.0.0:12345")

    while True:
        client_socket, addr = server.accept()
        wpa3_server = WPA3Server()
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_socket, addr, wpa3_server)
        )
        client_handler.start()


if __name__ == "__main__":
    main()
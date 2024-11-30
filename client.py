import socket
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64


class WPA3Client:
    def __init__(self):
        # Generate ECDH key pair for the client
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.anonce = None
        self.snonce = os.urandom(32)  # Generate random nonce
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


def main():
    # Create a client socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the AP
        client.connect(('localhost', 12345))
        print("[*] Connected to AP")

        wpa3_client = WPA3Client()

        # Step 1: Receive ANonce and AP public key
        data = client.recv(4096)
        wpa3_client.anonce = data[:32]
        ap_public_key = serialization.load_pem_public_key(data[32:])
        print("[*] Received ANonce and AP public key")

        # Step 2: Send SNonce and public key
        public_bytes = wpa3_client.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client.send(wpa3_client.snonce + public_bytes)
        print("[*] Sent SNonce and public key")

        # Step 3: Derive session key
        session_key = wpa3_client.derive_session_key(
            ap_public_key,
            wpa3_client.anonce,
            wpa3_client.snonce
        )
        print(f"[*] SESSION KEY (hex): {session_key.hex()}")

        # Step 4: Receive encrypted test message
        encrypted = client.recv(4096).decode()
        decrypted = wpa3_client.decrypt_message(encrypted)
        print(f"[*] Received encrypted packet: {encrypted}")
        print(f"[*] Decrypted packet: {decrypted}")

        # Send encrypted response
        response = "Secure connection established from Client!"
        encrypted_response = wpa3_client.encrypt_message(response)
        client.send(encrypted_response.encode())
        print(f"[*] Sent encrypted packet: {encrypted_response}")

        # Demonstrate a few packet exchanges
        packets = [
            "Hi, This is Kishor.",
            "This is project assignment 4",
            "Testing secure communication"
        ]

        for packet in packets:
            # Send encrypted packet
            encrypted_msg = wpa3_client.encrypt_message(packet)
            client.send(encrypted_msg.encode())
            print(f"\n[CLIENT] Sent encrypted packet: {encrypted_msg}")
            print(f"[CLIENT] Original message: {packet}")

            # Receive and decrypt response
            encrypted_response = client.recv(4096).decode()
            decrypted_response = wpa3_client.decrypt_message(encrypted_response)
            print(f"[SERVER] Received encrypted packet: {encrypted_response}")
            print(f"[SERVER] Decrypted message: {decrypted_response}")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()
        print("[*] Connection closed")


if __name__ == "__main__":
    main()
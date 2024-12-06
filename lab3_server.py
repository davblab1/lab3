import os
import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345

# Зберігаємо дані ключа в файл
def save_key_to_storage(key_data, filename):
    with open(filename, "wb") as file:
        file.write(key_data)

# Генерація приватного ключа для клієнта/сервера
def generate_private_key(curve):
    return ec.generate_private_key(curve)

# Шифрування повідомлення
def encrypt_data(key, message):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(message) + encryptor.finalize()
    return nonce, encrypted_data, encryptor.tag

# Дешифрування повідомлення
def decrypt_data(key, nonce, encrypted_data, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Генерація спільного секрету
def generate_shared_secret(private_key, public_key):
    return private_key.exchange(ec.ECDH(), public_key)

# Отримання симетричного ключа з використанням HKDF
def generate_symmetric_key(shared_secret):
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"secure_handshake",
    ).derive(shared_secret)

# Основна функція сервера
def server_main():
    server_private_key = generate_private_key(ec.SECP256R1())
    server_private_key_bytes = server_private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    server_public_key_bytes = server_private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Зберігаємо пари ключів у файли
    save_key_to_storage(server_private_key_bytes, "server_private_key.pem")
    save_key_to_storage(server_public_key_bytes, "server_public_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(5)
        print("[Server] Очікування клієнта...")
        conn, addr = server_socket.accept()
        with conn:
            print(f"[Server] З'єднання з {addr} встановлено.")

            # Отримання публічного ключа клієнта
            client_public_key_data = conn.recv(1024)
            client_public_key = load_pem_public_key(client_public_key_data)

            # Відправка публічного ключа сервера
            conn.sendall(server_public_key_bytes)

            # Генерація спільного секрету та симетричного ключа
            shared_secret = generate_shared_secret(server_private_key, client_public_key)
            symmetric_key = generate_symmetric_key(shared_secret)

            # Збереження симетричного ключа
            save_key_to_storage(symmetric_key, "server_symmetric_key.key")
            print("[Server] Спільний секрет узгоджено.")

            while True:
                encrypted_message = conn.recv(1024)
                if not encrypted_message:
                    break

                # Дешифрування повідомлення
                nonce, encrypted_data, tag = (
                    encrypted_message[:12],
                    encrypted_message[12:-16],
                    encrypted_message[-16:],
                )
                decrypted_message = decrypt_data(symmetric_key, nonce, encrypted_data, tag)
                print(f"[Server] Отримано: {decrypted_message.decode()}")

                # Відправка підтвердження клієнту
                response = "Повідомлення отримано.".encode("utf-8")
                nonce, encrypted_response, tag = encrypt_data(symmetric_key, response)
                conn.sendall(nonce + encrypted_response + tag)

if __name__ == "__main__":
    server_main()

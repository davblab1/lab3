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

# Функція збереження ключа в файл
def store_key_in_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

# Функція генерації приватного ключа
def create_private_key(curve):
    return ec.generate_private_key(curve)

# Функція для шифрування даних
def encrypt_message(key, message):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return nonce, encrypted_message, encryptor.tag

# Функція для дешифрування даних
def decrypt_message(key, nonce, encrypted_message, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message) + decryptor.finalize()

# Генерація спільного секрету
def generate_shared_secret(private_key, public_key):
    return private_key.exchange(ec.ECDH(), public_key)

# Отримання симетричного ключа через HKDF
def derive_symmetric_key(shared_secret):
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"secure_handshake",
    ).derive(shared_secret)

# Основна функція клієнта
def client_main():
    client_private_key = create_private_key(ec.SECP256R1())
    client_private_key_bytes = client_private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Зберігаємо ключі клієнта
    store_key_in_file(client_private_key_bytes, "client_private_key.pem")
    store_key_in_file(client_public_key_bytes, "client_public_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print("[Client] Підключення успішно встановлено.")

        # Відправляємо публічний ключ клієнта
        client_socket.sendall(client_public_key_bytes)

        # Отримуємо публічний ключ сервера
        server_public_key_data = client_socket.recv(1024)
        server_public_key = load_pem_public_key(server_public_key_data)

        # Генерація спільного секрету
        shared_secret = generate_shared_secret(client_private_key, server_public_key)
        symmetric_key = derive_symmetric_key(shared_secret)

        # Збереження симетричного ключа
        store_key_in_file(symmetric_key, "client_symmetric_key.key")
        print("[Client] Спільний секрет успішно отримано.")

        while True:
            message = input("[Client] Введіть повідомлення (або 'exit' для виходу): ")
            if message.lower() == "exit":
                break

            nonce, encrypted_msg, tag = encrypt_message(symmetric_key, message.encode())
            # Відправка зашифрованого повідомлення
            client_socket.sendall(nonce + encrypted_msg + tag)

            # Отримуємо підтвердження від сервера
            response_data = client_socket.recv(1024)
            nonce, encrypted_response, tag = (
                response_data[:12],
                response_data[12:-16],
                response_data[-16:],
            )
            decrypted_response = decrypt_message(symmetric_key, nonce, encrypted_response, tag)
            print(f"[Client] Відповідь сервера: {decrypted_response.decode()}")

if __name__ == "__main__":
    client_main()

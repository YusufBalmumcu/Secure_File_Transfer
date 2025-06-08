import socket
import os
from encryption import decrypt_aes_key, decrypt_file

HOST = '127.0.0.1'
PORT = 65432

def receive_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Dinleniyor: {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"Bağlantı: {addr}")
            data = b""
            while True:
                part = conn.recv(4096)
                if not part:
                    break
                data += part

            encrypted_key = data[:256]
            encrypted_data = data[256:]

            aes_key = decrypt_aes_key(encrypted_key, "../keys/private_key.pem")
            plaintext = decrypt_file(encrypted_data, aes_key)

            os.makedirs("received_files", exist_ok=True)
            with open("received_files/received_test.txt", "wb") as f:
                f.write(plaintext)

            print("Dosya alındı ve kaydedildi.")

if __name__ == "__main__":
    receive_file()

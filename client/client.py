import socket
from encryption import generate_aes_key, encrypt_file, encrypt_aes_key

HOST = '127.0.0.1'
PORT = 65432
FILE_TO_SEND = "test.txt"

def send_file():
    aes_key = generate_aes_key()
    encrypted_data = encrypt_file(FILE_TO_SEND, aes_key)
    encrypted_key = encrypt_aes_key(aes_key, "../keys/public_key.pem")

    payload = encrypted_key + encrypted_data

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(payload)
        print("Dosya gönderildi.")

if __name__ == "__main__":
    send_file()

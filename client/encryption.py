from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def generate_aes_key():
    return get_random_bytes(16)  # 128-bit

def encrypt_file(file_path, aes_key):
    with open(file_path, "rb") as f:
        data = f.read()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + encrypted_data

def encrypt_aes_key(aes_key, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad

def decrypt_aes_key(encrypted_key, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

def decrypt_file(encrypted_data, aes_key):
    iv = encrypted_data[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return plaintext

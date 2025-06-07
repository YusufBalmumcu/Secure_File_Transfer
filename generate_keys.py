# generate_keys.py
from Crypto.PublicKey import RSA
import os

os.makedirs("keys", exist_ok=True)

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("keys/private_key.pem", "wb") as f:
    f.write(private_key)

with open("keys/public_key.pem", "wb") as f:
    f.write(public_key)

print("RSA anahtarları oluşturuldu ve 'keys' klasörüne kaydedildi.")

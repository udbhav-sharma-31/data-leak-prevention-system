import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_aes(file_data: bytes):
    key = get_random_bytes(16)  # 128-bit key
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    # Combine nonce + tag + ciphertext
    encrypted = cipher.nonce + tag + ciphertext
    return encrypted, key


def decrypt_aes(encrypted_data: bytes, key: bytes):
    # Extract nonce (first 16), tag (next 16), rest is ciphertext
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data



# ===== RSA Key Pair Generation =====
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# ===== RSA Encryption / Decryption =====
def encrypt_rsa(file_data: bytes, public_key_data: bytes):
    pub_key = RSA.import_key(public_key_data)
    cipher = PKCS1_OAEP.new(pub_key)
    chunk_size = 190  # because RSA 2048 limit
    encrypted_chunks = [cipher.encrypt(file_data[i:i+chunk_size]) for i in range(0, len(file_data), chunk_size)]
    return b"".join(encrypted_chunks)

def decrypt_rsa(encrypted_data: bytes, private_key_data: bytes):
    priv_key = RSA.import_key(private_key_data)
    cipher = PKCS1_OAEP.new(priv_key)
    chunk_size = 256
    decrypted_chunks = [cipher.decrypt(encrypted_data[i:i+chunk_size]) for i in range(0, len(encrypted_data), chunk_size)]
    return b"".join(decrypted_chunks)

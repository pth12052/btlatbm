from Crypto.Cipher import DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import time

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

def rsa_encrypt(public_key, data_bytes):
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return base64.b64encode(cipher.encrypt(data_bytes)).decode()

def rsa_decrypt(private_key, encrypted_b64):
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    encrypted = base64.b64decode(encrypted_b64)
    return cipher.decrypt(encrypted)

def triple_des_encrypt(key, plaintext):
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    pad_len = 8 - len(plaintext.encode()) % 8
    pad_text = plaintext + chr(pad_len) * pad_len
    ciphertext = cipher.encrypt(pad_text.encode())
    return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

def triple_des_decrypt(key, iv_b64, ciphertext_b64):
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len].decode()

def sha256_hash(iv_b64, ciphertext_b64):
    combined = base64.b64decode(iv_b64) + base64.b64decode(ciphertext_b64)
    h = SHA256.new(combined)
    return h.hexdigest()

def sign_data(private_key, data_str):
    h = SHA256.new(data_str.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(public_key, data_str, signature_b64):
    h = SHA256.new(data_str.encode())
    try:
        signature = base64.b64decode(signature_b64)
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except:
        return False

# crypto_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_rsa_keys():
    """Tạo cặp khóa RSA 2048-bit."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def load_rsa_private_key(private_key_pem):
    """Tải khóa riêng RSA từ định dạng PEM."""
    return RSA.import_key(private_key_pem)

def load_rsa_public_key(public_key_pem):
    """Tải khóa công khai RSA từ định dạng PEM."""
    return RSA.import_key(public_key_pem)

def encrypt_aes_key(aes_key, public_rsa_key):
    """Mã hóa khóa AES bằng khóa công khai RSA của người nhận."""
    cipher_rsa = PKCS1_OAEP.new(public_rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key(encrypted_aes_key, private_rsa_key):
    """Giải mã khóa AES bằng khóa riêng RSA của người nhận."""
    cipher_rsa = PKCS1_OAEP.new(private_rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def encrypt_message_aes(message, aes_key):
    """Mã hóa tin nhắn bằng AES-256-CBC."""
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher_aes.encrypt(padded_message)
    return cipher_aes.iv, ciphertext

def decrypt_message_aes(ciphertext, iv, aes_key):
    """Giải mã tin nhắn bằng AES-256-CBC."""
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded_message = cipher_aes.decrypt(ciphertext)
    message = unpad(decrypted_padded_message, AES.block_size).decode('utf-8')
    return message

def calculate_hash(data):
    """Tính toán giá trị băm SHA-256 và trả về dạng bytes."""
    h = SHA256.new()
    h.update(data)
    return h.digest()

def sign_data(data, private_rsa_key):
    """Tạo chữ ký số cho dữ liệu bằng khóa riêng RSA."""
    data_hash_object = SHA256.new(data)
    signer = pkcs1_15.new(private_rsa_key)
    signature = signer.sign(data_hash_object)
    return signature

def verify_signature(data, signature, public_rsa_key):
    """Kiểm tra chữ ký số bằng khóa công khai RSA."""
    data_hash_object = SHA256.new(data)
    try:
        verifier = pkcs1_15.new(public_rsa_key)
        verifier.verify(data_hash_object, signature)
        return True
    except (ValueError, TypeError):
        return False
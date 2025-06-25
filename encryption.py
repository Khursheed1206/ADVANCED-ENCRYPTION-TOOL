from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path: str, password: str, output_path: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    with open(input_path, 'rb') as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding (PKCS7)
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len]) * pad_len

    encrypted = encryptor.update(data) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted)

def decrypt_file(input_path: str, password: str, output_path: str = None):
    with open(input_path, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    encrypted = raw[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    with open(output_path, 'wb') as f:
        f.write(decrypted)
    if not output_path:
        if input_path.lower().endswith('.enc'):
            output_path = input_path[:-4]
        else:
            output_path = input_path + '.decrypted'

    with open(output_path, 'wb') as f:
        f.write(decrypted)

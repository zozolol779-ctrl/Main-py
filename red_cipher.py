import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class RedCipher:
    def __init__(self, key_material):
        # ELITE FIX: Match ghost.py's sha256 hashing
        self.key = hashlib.sha256(key_material).digest()

    def encrypt(self, raw_data):
        if isinstance(raw_data, str):
            raw_data = raw_data.encode()
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(raw_data, AES.block_size))
        return base64.b64encode(iv + encrypted_data).decode("utf-8")

    def decrypt(self, enc_data):
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[: AES.block_size]
        cipher_text = enc_data[AES.block_size :]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(cipher_text), AES.block_size).decode("utf-8")

    def derive_key(self, salt: str):
        """Derives a sub-key for specific sessions or fragments."""
        return hashlib.sha256(self.key + salt.encode()).digest()

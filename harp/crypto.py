import base64
import hashlib

from cryptography.fernet import Fernet


def _fernet(secret_key: str) -> Fernet:
    key = hashlib.sha256(secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_token(token: str, secret_key: str) -> str:
    return _fernet(secret_key).encrypt(token.encode()).decode()


def decrypt_token(encrypted: str, secret_key: str) -> str:
    from cryptography.fernet import InvalidToken
    try:
        return _fernet(secret_key).decrypt(encrypted.encode()).decode()
    except InvalidToken:
        raise ValueError("Stored token could not be decrypted — please re-save your API token in your profile.")

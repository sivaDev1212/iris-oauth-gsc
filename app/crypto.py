from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .config import get_settings


def _fernet() -> MultiFernet:
    keys = [k.strip() for k in get_settings().token_encryption_keys.split(",") if k.strip()]
    if not keys:
        raise RuntimeError("TOKEN_ENCRYPTION_KEYS is not set")
    # First key encrypts, every key can decrypt -> zero-downtime key rotation.
    return MultiFernet([Fernet(k.encode()) for k in keys])


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Stored token cannot be decrypted (wrong/rotated-out key?)") from exc


def rotate(ciphertext: str) -> str:
    """Re-encrypt with the current primary key."""
    return _fernet().rotate(ciphertext.encode()).decode()

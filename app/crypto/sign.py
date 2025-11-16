# app/crypto/sign.py
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(path: str, password: bytes = None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def rsa_sign(priv_key, data: bytes) -> str:
    """
    Sign raw bytes and return base64 signature string.
    """
    sig = priv_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

def rsa_verify(pub_key, data: bytes, sig_b64: str) -> bool:
    """
    Verify base64 signature against raw data bytes using public key object.
    Returns True/False.
    """
    sig = base64.b64decode(sig_b64.encode())
    try:
        pub_key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

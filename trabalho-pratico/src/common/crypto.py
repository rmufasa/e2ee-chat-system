from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# generate key pair used to certify client (static) and other key pair to derive shared secret (ephemeral), public and private keys in here ARE NOT used directly for encryption
def generate_ephemeral_keypair():
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key()
    return private, public

def generate_identity_keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public

def compute_shared_secret(private, peer_public_bytes):
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private.exchange(peer_public)

def derive_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat-app',
    )
    return hkdf.derive(shared_secret)

def encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

def decrypt(key, nonce, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def hash_password(password):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )

    key = kdf.derive(password.encode())

    return base64.b64encode(salt + key).decode()

def verify_password(stored, password):
    data = base64.b64decode(stored.encode())
    salt = data[:16]
    stored_key = data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )

    try:
        kdf.verify(password.encode(), stored_key)
        return True
    except:
        return False
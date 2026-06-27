import json
from cryptography.hazmat.primitives import serialization
from common.crypto import generate_identity_keypair, encrypt, decrypt
import base64
import os

DB_FILE = "users.json"


def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)


def load_or_create_ca():
    if os.path.exists("ca_private.pem"):
        with open("ca_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key, public_key = generate_identity_keypair()
        with open("ca_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    return private_key, private_key.public_key()

def export_ca_public_key(public_key):
    with open("ca_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_certificates():
    try:
        with open("certificates.json", "r") as f:
            return json.load(f)
    except:
        return {}


def save_certificates(certs):
    with open("certificates.json", "w") as f:
        json.dump(certs, f)


def save_local_sessions(username, sessions, local_storage_key):
    b64_sessions = {k: base64.b64encode(v).decode() for k, v in sessions.items()}
    json_data = json.dumps(b64_sessions)
    nonce, ciphertext = encrypt(local_storage_key, json_data)
    with open(f"{username}_sessions.enc", "wb") as f:
        f.write(nonce + ciphertext)


def load_local_sessions(username, local_storage_key):
    filename = f"{username}_sessions.enc"
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = f.read()
            nonce = data[:12]
            ciphertext = data[12:]
            try:
                json_data = decrypt(local_storage_key, nonce, ciphertext)
                b64_sessions = json.loads(json_data)
                return {k: base64.b64decode(v.encode()) for k, v in b64_sessions.items()}
            except Exception:
                print("\n[ERRO FATAL] Não foi possível decifrar as chaves locais. Password errada ou ficheiro corrompido.")
                return {}
    return {}

def save_local_groups(username, groups, local_storage_key):
    # Converter chaves para Base64 e criar a string JSON
    b64_groups = {k: base64.b64encode(v).decode() for k, v in groups.items()}
    json_data = json.dumps(b64_groups)
    
    # Encriptar o JSON usando a chave gerada pela password
    nonce, ciphertext = encrypt(local_storage_key, json_data)
    
    # Guardar o ficheiro cifrado (usamos _groups.enc)
    with open(f"{username}_groups.enc", "wb") as f:
        f.write(nonce + ciphertext)

def load_local_groups(username, local_storage_key):
    filename = f"{username}_groups.enc"
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            data = f.read()
            nonce = data[:12]
            ciphertext = data[12:]
            
            try:
                # Tentar decifrar o conteúdo
                json_data = decrypt(local_storage_key, nonce, ciphertext)
                
                # Converte de volta
                b64_groups = json.loads(json_data)
                return {k: base64.b64decode(v.encode()) for k, v in b64_groups.items()}
            except Exception:
                print("\n[ERRO FATAL] Não foi possível decifrar as chaves de grupo locais.")
                return {}
    return {}

def load_or_create_identity_keypair(username):
    priv_file = f"{username}_private.pem"

    if os.path.exists(priv_file):
        with open(priv_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key, public_key = generate_identity_keypair()
        with open(priv_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return private_key, private_key.public_key()

    return private_key, private_key.public_key()
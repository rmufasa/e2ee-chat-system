import socket
import threading
import json
import base64
from common.Datagram import Datagram
from common.crypto import generate_ephemeral_keypair, compute_shared_secret, derive_key, encrypt, decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from server import persistance_functions
import ssl
import os

HOST = '127.0.0.1'
PORT = 12345

# load CA public key
with open("ca_public.pem", "rb") as f:
    ca_public_key = serialization.load_pem_public_key(f.read())

# create client and TLS context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations("server_cert.pem")
context.check_hostname = False
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(raw_socket, server_hostname="localhost")
client.connect((HOST, PORT))

# store own username 
my_username = None

# trusted peers: username -> {peer's public key, personal ephemeral private key, personal ephemeral public key}
trusted_peers = {} 

# session keys: username -> session key
session_keys = {}

# counters to update session key after n messages: username -> count (so after atleast one of the user gets to n limit, session keys expires for both) 
n_limit = 5
message_counters = {}

# groups management: group name -> group key
group_keys = {}

# convert public key to bytes
def get_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def print_menu():
    print("\n=== COMANDOS DISPONÍVEIS ===")
    print("/add <user>                   - Adiciona um utilizador aos contactos")
    print("/remove <user>                - Remove um utilizador dos contactos")
    print("/list_contacts                - Mostra a tua lista de contactos")
    print("/session <user>               - Inicia uma sessão segura com um contacto")
    print("/msg <user> <texto>           - Envia uma mensagem cifrada para a sessão")
    print("/add_group <nome>             - Cria um novo grupo")
    print("/group_invite <nome> <user>   - Convida um utilizador para o grupo")
    print("/group_msg <nome> <texto>     - Envia uma mensagem cifrada para o grupo")
    print("/leave_group <nome>           - Sai de um grupo")
    print("/list_groups                  - Mostra os grupos a que pertences")
    print("/quit ou /exit                - Sai da aplicação")
    print("*(Prime a tecla Enter vazia para ver este menu novamente)*")
    print("============================\n")

# login phase (handled in main thread only)
buffer = ""
while True:
    try:
        data = client.recv(4096)
        if not data:
            print("Disconnected from server")
            exit()
    
        buffer += data.decode()

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if not line.strip():
                continue
            
            dgram = Datagram.decode(line.encode())

            if dgram.command == "request_username":
                username = input("Username: ")
                my_username = username
                password = input("Password: ")

                global local_storage_key
                # Transformar a password numa chave AES válida de 32 bytes
                local_storage_key = derive_key(password.encode())
                
                login_attempt = json.dumps({
                    "username": username,
                    "password": password
                })
                client.send(Datagram.login(login_attempt).encode())
            
            elif dgram.command == "login_ok":
                print(f"[OK] {dgram.content}")
                print_menu()
                
                session_keys = persistance_functions.load_local_sessions(my_username, local_storage_key)
                group_keys = persistance_functions.load_local_groups(my_username, local_storage_key)
                # Inicializar os contadores de mensagens para as sessões carregadas
                for peer in session_keys:
                    if peer not in message_counters:
                        message_counters[peer] = 0
                # client key pair
                private_key, public_key = persistance_functions.load_or_create_identity_keypair(my_username)

                # send public key to server
                public_bytes = get_public_bytes(public_key)
                public_key_b64 = base64.b64encode(public_bytes).decode() # raw bytes -> b64 bytes -> b64 string
                client.send(Datagram.register_key(public_key_b64).encode())

                break # sucessful login
            
            elif dgram.command == "error":
                print(f"[ERROR] {dgram.content}")
        else:
            continue
        break

    except Exception as e:
        print(f"Login error: {e}")
        client.close()
        exit()
            


# receive thread
def receive():
    buffer = ""

    while True:
        try:
            data = client.recv(4096)
            if not data:
                print("\nDisconnected from server")
                break

            buffer += data.decode()

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue
                dgram = Datagram.decode(line.encode())

                # receive message
                if dgram.command == "msg":
                    # check if sender has session key with receiver
                    sender = dgram.from_user
                    if sender not in session_keys:
                        # session may never have been created or may have expired
                        client.send(Datagram.no_session_inform(sender).encode())
                        print(f"\n[INFO] You received a message from {sender} but the session expired. Run /session {sender}")
                        continue

                    key = session_keys[sender]
                    data = base64.b64decode(dgram.content.encode()) # b64 string -> b64 bytes -> raw bytes
                    nonce = data[:12]
                    ciphertext = data[12:]

                    try:
                        plaintext = decrypt(key, nonce, ciphertext)
                    except Exception:
                        print("Decryption failed")
                        continue

                    print(f"\n[{sender}] {plaintext}")

                # success
                elif dgram.command == "ack":
                    print(f"\n[OK] {dgram.content}")

                # error
                elif dgram.command == "error":
                    print(f"\n[ERROR] {dgram.content}")
                
                # info
                elif dgram.command == "info":
                    print(f"\n[INFO] {dgram.content}")

                # list contacts (or users)
                elif dgram.command == "contacts_list":
                    print(f"\nContacts: {dgram.content}")

                # receive requested session
                elif dgram.command == "session_response":
                    peer = dgram.from_user

                    cert = json.loads(dgram.content)

                    username = cert.get("username")
                    public_key_b64 = cert.get("public_key")
                    signature_b64 = cert.get("signature")

                    data = (username + public_key_b64).encode()
                    signature = base64.b64decode(signature_b64.encode()) # b64 string -> b64 bytes -> raw bytes

                    if username != peer:
                        print("Certificate username mismatch!")
                        continue
                    
                    # verify signature (bind public key received to an identity via trust of CA)
                    try:
                        ca_public_key.verify(signature, data)
                    except Exception:
                        print("Invalid certificate!")
                        continue

                    # identity has been confirmed, store trusted peer and generate ephemeral key pair
                    eph_priv, eph_pub = generate_ephemeral_keypair()
                    
                    # trusted peer info
                    peer_info = {
                        "peer_public_key": public_key_b64, # peer's public key
                        "my_eph_priv": eph_priv, # ephemeral private key
                        "my_eph_pub": eph_pub # epehemeral public key
                    }

                    trusted_peers[peer] = peer_info
                    
                    eph_public_bytes = get_public_bytes(eph_pub)
                    eph_b64 = base64.b64encode(eph_public_bytes).decode() # raw bytes -> b64 bytes -> b64 string
                    data = (my_username + eph_b64).encode()

                    # sign with personal private key
                    signature = private_key.sign(data)

                    payload = {
                        "username": my_username,
                        "eph_public_key": eph_b64,
                        "signature": base64.b64encode(signature).decode() # raw bytes -> b64 bytes -> b64 string
                    }

                    # payload object to json formatted string
                    payload_package = json.dumps(payload)

                    client.send(Datagram.send_session_ephemeral(peer, payload_package).encode())
                
                elif dgram.command == "session_ephemeral":
                    payload = json.loads(dgram.content)

                    username = payload.get("username")
                    eph_b64 = payload.get("eph_public_key")
                    signature_b64 = payload.get("signature")

                    # verify we have trusted peer beforehand
                    eph_info = trusted_peers.get(username)

                    if not eph_info:
                        print("Missing identity key, cannot verify")
                        continue

                    public_key_b64 = eph_info.get("peer_public_key")
                    my_eph_priv = eph_info.get("my_eph_priv")

                    peer_public_bytes = base64.b64decode(public_key_b64.encode()) # b64 string -> b64 bytes -> raw bytes
                    peer_public_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_public_bytes) # raw bytes -> public key

                    data = (username + eph_b64).encode()
                    signature = base64.b64decode(signature_b64.encode()) # b64 string -> b64 bytes -> raw bytes

                    # verify signature (bind ephemeral public key received to an identity who we trust via trust of CA)
                    try:
                        peer_public_key.verify(signature, data)
                    except:
                        print("Invalid ephemeral payload!")
                        continue

                    peer_eph_public_bytes = base64.b64decode(eph_b64.encode()) # b64 string -> b64 bytes -> raw bytes
                    shared_secret = compute_shared_secret(my_eph_priv,peer_eph_public_bytes)
                    session_key = derive_key(shared_secret)
                    # store session key
                    session_keys[username] = session_key
                    persistance_functions.save_local_sessions(my_username, session_keys, local_storage_key)

                    # initiate message counter
                    message_counters[username] = 0
                    
                    print(f"[SESSION] Secure session with {username} established")
                elif dgram.command == "no_session":
                    # in here peer is the original message receiver, it told server to inform original messsage sender (this client) that he doesn't have session with it
                    peer = dgram.from_user
                    if peer in session_keys:
                        del session_keys[peer]
                        persistance_functions.save_local_sessions(my_username, session_keys, local_storage_key)
                    print(f"\n[INFO] {peer} has no session with you. Run /session {peer}.")
                
                elif dgram.command == "group_invite_deliver":
                    sender = dgram.from_user
                    payload = json.loads(dgram.content)
                    group_name = payload.get("group_name")
                    enc_group_key = payload.get("enc_group_key")

                    # check if there is session with sender
                    if sender not in session_keys:
                        client.send(Datagram.no_session_inform(sender))
                        continue

                    # get group key
                    key = session_keys[sender]
                    data = base64.b64decode(enc_group_key.encode()) # b64 string -> b64 bytes -> raw bytes
                    nonce = data[:12]
                    ciphertext = data[12:]

                    try:
                        plaintext = decrypt(key, nonce, ciphertext)
                    except Exception:
                        print("Decryption failed")
                        continue
                    
                    # effectively accept invitation
                    group_key = base64.b64decode(plaintext.encode()) # b64 string -> b64 bytes -> raw bytes
                    group_keys[group_name] = group_key
                    persistance_functions.save_local_groups(my_username, group_keys, local_storage_key)

                    client.send(Datagram.accept_invite(group_name).encode())
                
                elif dgram.command == "group_msg":
                    sending_payload = json.loads(dgram.from_user)
                    sender = sending_payload.get("sender")
                    if(sender != my_username):
                        group_name = sending_payload.get("group_name")

                        # check if receiver is in group
                        if group_name not in group_keys:
                            continue
                        
                        key = group_keys[group_name]
                        data = base64.b64decode(dgram.content.encode()) # b64 string -> b64 bytes -> raw bytes
                        nonce = data[:12]
                        ciphertext = data[12:]

                        try:
                            plaintext = decrypt(key, nonce, ciphertext)
                        except Exception:
                            print("Decryption failed")
                            continue
                        print(f"\n[{sender} via {group_name}] {plaintext}")

                
                elif dgram.command == "ack_group":
                    group_name = dgram.content
                    group_key = os.urandom(32)
                    group_keys[group_name] = group_key
                    persistance_functions.save_local_groups(my_username, group_keys, local_storage_key)
                    
                    print(f"Group {group_name} has been created")



                print("=> ", end="", flush=True)

        except Exception as e:
            print(f"Receive error: {e}")
            break


threading.Thread(target=receive, daemon=True).start()

# send loop
while True:
    user_input = input("=> ")
    
    if not user_input: # Se o utilizador só carregou no Enter
        print_menu()
        continue

    if user_input.startswith("/msg "):
        try:
            _, to_user, content = user_input.split(" ", 2)

            # check if sender has session key with receiver
            if to_user not in session_keys:
                print("No secure session. Run /session <user>")
                continue

            # check if message limit was reached
            if message_counters[to_user] >= n_limit:
                del session_keys[to_user]
                persistance_functions.save_local_sessions(my_username, session_keys, local_storage_key)
                message_counters[to_user] = 0
                print("Session expired. Run /session again.")
                continue

            message_counters[to_user] += 1
            
            key = session_keys[to_user]
            nonce, ciphertext = encrypt(key,content)
            payload = base64.b64encode(nonce + ciphertext).decode() # raw bytes -> b64 bytes -> b64 string
            client.send(Datagram.msg(None, to_user, payload).encode()) # sender should not be trusted on who he is based on from_user camp but rather on connection that server holds
        except ValueError:
            print("Correct use: /msg <username> <message>")

    elif user_input.startswith("/add "):
        try:
            contact = user_input.split(" ", 1)[1]
            client.send(Datagram.add(contact).encode())
        except ValueError:
            print("Correct use: /add <username>")

    elif user_input.startswith("/remove "):
        try:
            contact = user_input.split(" ", 1)[1]
            client.send(Datagram.remove(contact).encode())
        except ValueError:
            print("Correct use: /remove <username>")

    elif user_input == "/list_contacts":
        client.send(Datagram.list_contacts().encode())
    
    elif user_input.startswith("/session "):
        try:
            target_user = user_input.split(" ", 1)[1]

            client.send(Datagram.request_session(target_user).encode())
        except ValueError:
            print("Correct use: /session <username>")

    elif user_input.startswith("/add_group "):
        try:
            group_name = user_input.split(" ", 1)[1]

            client.send(Datagram.add_group(group_name).encode())
        except ValueError:
            print("Correct use: /add_group <group_name>")
    
    elif user_input.startswith("/group_invite "):
        try:
            _, group_name, to_user = user_input.split(" ", 2)
            # check if sender is in group
            if group_name not in group_keys:
                print("You are not in this group.")
                continue

            # check if sender has session key with receiver
            if to_user not in session_keys:
                print("No secure session. Run /session <user>")
                continue
            
            key = session_keys[to_user]
            content = group_keys[group_name]
            plaintext = base64.b64encode(content).decode() # raw bytes -> b64 bytes -> b64 string
            nonce, ciphertext = encrypt(key,plaintext)
            payload = base64.b64encode(nonce + ciphertext).decode() # raw bytes -> b64 bytes -> b64 string
            # group name + encrypted group key
            full_payload = {
                "group_name": group_name,
                "enc_group_key": payload            
            }

            # payload object to json formatted string
            payload_package = json.dumps(full_payload)

            client.send(Datagram.group_invite(to_user, payload_package).encode())
        except ValueError:
            print("Usage: /group_invite <group_name> <username>")
    
    elif user_input.startswith("/group_msg "):
        try:
            _, group_name, content = user_input.split(" ", 2)

            # check if sender is in group
            if group_name not in group_keys:
                print("You are not in that group.")
                continue        
            
            sender_payload = {
                "sender": my_username,
                "group_name": group_name          
            }

            # payload object to json formatted string
            sender_payload_package = json.dumps(sender_payload)

            key = group_keys[group_name]
            nonce, ciphertext = encrypt(key,content)
            payload = base64.b64encode(nonce + ciphertext).decode() # raw bytes -> b64 bytes -> b64 string
            client.send(Datagram.group_msg(sender_payload_package,payload).encode()) 
        except ValueError:
            print("Correct use: /group_msg <group_name> <message>")

    elif user_input.startswith("/leave_group "):
        try:
            group_name = user_input.split(" ", 1)[1]

            # check if sender is in group
            if group_name not in group_keys:
                print("You are not in that group.")
                continue        

            # leave group
            del group_keys[group_name]
            persistance_functions.save_local_groups(my_username, group_keys, local_storage_key)
            client.send(Datagram.leave_group(group_name).encode())
        except ValueError:
            print("Correct use: /leave_group <group_name>")
    
    elif user_input.startswith("/list_groups"):
        # list groups
        for group in group_keys:
            print(f"{group}\n")
        

            
    elif user_input in ["/quit", "/exit"]:
        client.send(Datagram.quit().encode())
        client.close()
        break

    else:
        print("Comandos: /msg /add /remove /list_contacts /session /add_group /group_invite /group_msg /leave_group /list_groups /quit")
    
    
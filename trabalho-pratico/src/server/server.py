import socket
import threading
from common.Datagram import Datagram
from . import persistance_functions
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
import ssl
from common.crypto import hash_password, verify_password


HOST = '127.0.0.1'
PORT = 12345


# persisted users (username and contacts list)
users = persistance_functions.load_users()

# active clients: username -> connection 
clients = {}

# certificates: username -> certificates
certificates = persistance_functions.load_certificates()

# groups management: group_name -> list of members
groups = {}

# thread safety
clients_lock = threading.Lock()
users_lock = threading.Lock()
certificates_lock = threading.Lock()

# CA(central authority) key pair
ca_private_key, ca_public_key = persistance_functions.load_or_create_ca()
# export CA public key for it's distribution
persistance_functions.export_ca_public_key(ca_public_key)

# handle client
def handle_client(conn, addr):
    print(f"Client {addr} connected")
    buffer = ""


    # request username 
    while True:
        conn.send(Datagram.request_username().encode())

        data = conn.recv(4096)
        if not data:
            break
        
        buffer += data.decode()

        
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if not line.strip():
                continue

            datagram = Datagram.decode(line.encode())

            if datagram.command != "login" or not datagram.content:
                conn.send(Datagram.error("Expected login").encode())
                continue

            login_attempt = json.loads(datagram.content)
            username = login_attempt.get("username")
            password = login_attempt.get("password")

            with clients_lock:
                if username in clients:
                    conn.send(Datagram.error("Username already online").encode())
                    continue
            
            with users_lock:
                if username in users:
                    # user is registered, check password
                    if not verify_password(users[username]["password"], password):
                        conn.send(Datagram.error("Incorrect password").encode())
                        continue


                if username not in users:
                    # user is not registered, register it
                    stored_password = hash_password(password)
                    users[username] = {"contacts": [], "password": stored_password}
                    persistance_functions.save_users(users)

            # success -> break loop
            break
        else:
            continue
        break
    
    with clients_lock:
        clients[username] = conn
    print(f"{username} connected")
    conn.send(Datagram.login_ok(f"Welcome {username}").encode())
    
    with users_lock:
        pending = users[username].get("offline_messages", [])
        if pending:
            conn.send(Datagram.info(f"You have {len(pending)} pending messages/invites!").encode())
            for msg_dict in pending:
                conn.send((json.dumps(msg_dict) + "\n").encode())
            users[username]["offline_messages"] = []
            persistance_functions.save_users(users)

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data.decode()

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue

                datagram = Datagram.decode(line.encode())

                # message
                if datagram.command == "msg":
                    target = datagram.to_user

                    # cannot message yourself
                    if target == username:
                        conn.send(Datagram.error("You cannot message yourself").encode())
                        continue

                    # user must exist
                    with users_lock:
                        if target not in users:
                            conn.send(Datagram.error("User not found").encode())
                            continue

                        # must be in contacts
                        if target not in users[username]["contacts"]:
                            conn.send(Datagram.error("User not in your contacts").encode())
                            continue

                    # must be online
                    with clients_lock:
                        target_conn = clients.get(target)
                        
                    # send message
                    msg = Datagram.msg(username, target, datagram.content)

                    if not target_conn:
                        with users_lock:
                            if "offline_messages" not in users[target]:
                                users[target]["offline_messages"] = []
                            users[target]["offline_messages"].append(msg.to_dict())
                            persistance_functions.save_users(users)
                        conn.send(Datagram.info(f"User {target} is offline. Message saved.").encode())
                        continue

                    try:
                        target_conn.send(msg.encode())
                    except:
                        conn.send(Datagram.error("Failed to deliver message").encode())
                
                # add contact 
                elif datagram.command == "add":
                    contact = datagram.contact

                    if contact == username:
                        conn.send(Datagram.error("You cannot add yourself").encode())
                        continue

                    with users_lock:
                        if contact not in users:
                            conn.send(Datagram.error("User does not exist").encode())
                        else:
                            if contact not in users[username]["contacts"]:
                                users[username]["contacts"].append(contact)
                                persistance_functions.save_users(users)
                                conn.send(Datagram.ack(f"{contact} added").encode())
                            else:
                                conn.send(Datagram.error(f"Already in contacts").encode())

                # remove contact 
                elif datagram.command == "remove":
                    contact = datagram.contact

                    with users_lock:
                        if contact in users[username]["contacts"]:
                            users[username]["contacts"].remove(contact)
                            persistance_functions.save_users(users)
                            conn.send(Datagram.ack(f"{contact} removed").encode())
                        else:
                            conn.send(Datagram.error("Not in contacts").encode())

                # list contacts
                elif datagram.command == "list_contacts":
                    with users_lock:
                        contacts = list(users[username]["contacts"])
                    conn.send(Datagram.contacts_list(", ".join(contacts)).encode())
                
                # register key 
                elif datagram.command == "register_key":
                    if username in certificates:
                        conn.send(Datagram.info("You are already certified").encode())
                        continue

                    public_key_b64 = datagram.content

                    # create data to sign
                    data = (username + public_key_b64).encode()
                    
                    # sign with CA private_key
                    signature = ca_private_key.sign(data)

                    cert = {
                        "username": username,
                        "public_key": public_key_b64,
                        "signature": base64.b64encode(signature).decode() # raw bytes -> b64 bytes -> b64 string
                    }

                    with certificates_lock:
                        certificates[username] = cert
                        persistance_functions.save_certificates(certificates)

                    conn.send(Datagram.ack("Certificate registered").encode())
                
                elif datagram.command == "request_session":
                    target = datagram.to_user

                    # cannot message yourself
                    if target == username:
                        conn.send(Datagram.error("You cannot message yourself").encode())
                        continue

                    # user must exist
                    with users_lock:
                        if target not in users:
                            conn.send(Datagram.error("User not found").encode())
                            continue

                        # must be in contacts
                        if target not in users[username]["contacts"]:
                            conn.send(Datagram.error("User not in your contacts").encode())
                            continue
                        
                    with clients_lock:
                        target_conn = clients.get(target)
                    
                    # must be online
                    if not target_conn:
                        conn.send(Datagram.error("User offline").encode())
                        continue

                    with certificates_lock:
                        sender_cert = certificates.get(username)
                        target_cert = certificates.get(target)

                    if not sender_cert or not target_cert:
                        conn.send(Datagram.error("Missing certificate").encode())
                        continue


                    # certificate objects to json formatted string
                    sender_cert_package = json.dumps(sender_cert)
                    target_cert_package = json.dumps(target_cert)

                    # server sends to sender target certificate
                    conn.send(Datagram.session_response(target, target_cert_package).encode())
                    # server sends to target certificate
                    target_conn.send(Datagram.session_response(username, sender_cert_package).encode())
                
                elif datagram.command == "no_session_inform":
                    # original message sender
                    target = datagram.to_user

                    with clients_lock:
                        sender_conn = clients.get(target)

                    if sender_conn:
                        # inform original message sender that original message receiver session has expired
                        sender_conn.send(Datagram.no_session(username).encode())

                elif datagram.command == "send_session_ephemeral":
                    target = datagram.to_user

                    with clients_lock:
                        target_conn = clients.get(target)
                        
                    if not target_conn:
                        
                        eph_msg = Datagram.session_ephemeral(datagram.content)
                        
                        with users_lock:
                            if "offline_messages" not in users[target]:
                                users[target]["offline_messages"] = []
                            users[target]["offline_messages"].append(eph_msg.to_dict())
                            persistance_functions.save_users(users)
                        conn.send(Datagram.info(f"User {target} is offline. Message saved.").encode())
                        continue
                    
                    try:
                        target_conn.send(Datagram.session_ephemeral(datagram.content).encode())
                    except:
                        conn.send(Datagram.error("Failed to deliver ephemeral").encode())
                
                elif datagram.command == "add_group":
                    group_name = datagram.content
                    if group_name in groups:
                        conn.send(Datagram.error("Group already exists").encode())
                        continue

                    groups[group_name] = {
                        "owner": username,
                        "members": [username]
                    }

                    conn.send(Datagram.ack_group(group_name).encode())
                
                elif datagram.command == "group_invite":
                    target = datagram.to_user
                    payload = json.loads(datagram.content)
                    group_name = payload.get("group_name")

                    # check if group exists
                    if group_name not in groups:
                        conn.send(Datagram.error("That group does not exist").encode()) 
                        continue

                    # check if sender is "admin"
                    admin = groups[group_name].get("owner")
                    members = groups[group_name].get("members")
                    if username != admin:
                        conn.send(Datagram.error("You are not this group's owner. You cannot add new users.").encode())
                        continue
                    
                    # check if target is already in group
                    if target in members:
                        conn.send(Datagram.error("The user you are trying to add is already in the group.").encode())
                        continue

                    with clients_lock:
                        target_conn = clients.get(target)
                    # check if target is online
                    if not target_conn:
                        
                        invite_msg = Datagram.group_invite_deliver(username, datagram.content)
                        
                        with users_lock:
                            if "offline_messages" not in users[target]:
                                users[target]["offline_messages"] = []
                            users[target]["offline_messages"].append(invite_msg.to_dict())
                            persistance_functions.save_users(users)
                        conn.send(Datagram.info(f"User {target} is offline. Message saved.").encode())
                        continue

                    # send invite 
                    target_conn.send(Datagram.group_invite_deliver(username, datagram.content).encode())
                
                elif datagram.command == "accept_invite":
                    group_name = datagram.content
                    
                    # add user to server groups management list
                    member_list = groups[group_name].get("members")
                    member_list.append(username)

                    for member in member_list:
                        with clients_lock:
                            target_conn = clients.get(member)
                        # inform all group users
                        target_conn.send(Datagram.info(f"New user {username} was added to the {group_name} group").encode())
                
                elif datagram.command == "group_msg":
                    sending_payload = json.loads(datagram.from_user)
                    group_name = sending_payload.get("group_name")

                    if group_name not in groups:
                        conn.send(Datagram.error("That group does not exist").encode()) 
                        continue
                    
                    if username not in groups[group_name]["members"]:
                        conn.send(Datagram.error("You are not in this group").encode()) 
                        continue
                    
                    g_msg = Datagram.group_msg(datagram.from_user, datagram.content)

                    # send message to all group members
                    member_list = groups[group_name].get("members")
                    for member in member_list:
                        if member == username:
                            continue
                        with clients_lock:
                            target_conn = clients.get(member)
                        # inform all group users
                        if target_conn:
                            target_conn.send(Datagram.group_msg(datagram.from_user,datagram.content).encode())
                        else:
                            with users_lock:
                                if "offline_messages" not in users[member]:
                                    users[member]["offline_messages"] = []
                                users[member]["offline_messages"].append(g_msg.to_dict())
                                persistance_functions.save_users(users)
                                
                elif datagram.command == "leave_group":
                    group_name = datagram.content

                    if group_name not in groups:
                        conn.send(Datagram.error("That group does not exist").encode()) 
                        continue

                    if username not in groups[group_name]["members"]:
                        conn.send(Datagram.error("You are not in this group").encode()) 
                        continue
                    
                    groups[group_name]["members"].remove(username)

                    # if all group remains without users delete it 
                    if len(groups[group_name]["members"]) == 0:
                        del groups[group_name]
                    

                # quit
                elif datagram.command == "quit":
                    break

                else:
                    conn.send(Datagram.error("Unknown command").encode())
    except Exception as e:
        print(f"Error: {e}")

    finally:
        print(f"{username} disconnected")

        # remove user from all it's groups
        #for group in groups:
        #    if username in groups[group]["members"]:
        #        groups[group]["members"].remove(username)
        #        # if all group remains without users delete it 
        #        if len(groups[group]["members"]) == 0:
        #            del groups[group]

        with clients_lock:
            if username in clients:
                del clients[username] # client not active anymore
        conn.close()    



# create server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

# create TLS context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

context.load_cert_chain(
    certfile="server_cert.pem",
    keyfile="server_key.pem"
)

print("Server (TLS) listening...")

# accept client connection
while True:
    conn, addr = server.accept()

    try:
        secure_conn = context.wrap_socket(conn, server_side=True)
        threading.Thread(
            target=handle_client,
            args=(secure_conn, addr),
            daemon=True
        ).start()
    except ssl.SSLError as e:
        print(f"TLS error: {e}")
        conn.close()
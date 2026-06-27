import json
import base64

class Datagram:
    def __init__(self, command, from_user=None, to_user=None, content=None, contact=None):
        """
        datagram fields:
            - command: msg, add, remove, list_contacts, quit, request_username, login, ack, register_key, request_session, session_response
            - from_user: sender username (msg)
            - to_user: receiver username (msg)
            - content: message content (msg)
            - contact: contact username (add,remove)
        """

        self.command = command
        self.from_user = from_user
        self.to_user = to_user
        self.content = content
        self.contact = contact

    def to_dict(self):
        """convert the datagram into a dictionary for json serialization"""
        data = {}
        data["command"] = self.command
        if self.from_user is not None:
            data["from"] = self.from_user
        if self.to_user is not None:
            data["to"] = self.to_user
        if self.content is not None:
            data["content"] = self.content
        if self.contact is not None:
            data["contact"] = self.contact
        return data
    
    def encode(self):
        """convert the datagram to json bytes ready to send over a socket"""
        return (json.dumps(self.to_dict()) + "\n").encode()
    
    @staticmethod
    def decode(data_bytes):
        """ convert json bytes received from a socket into a datagram object. 
            if the json is invalid, return a datagram with command='error'.
        """
        try:
            data = json.loads(data_bytes.decode())
            return Datagram(
                command = data.get("command"),
                from_user = data.get("from"),
                to_user = data.get("to"),
                content = data.get("content"),
                contact= data.get("contact"),
            )
        except json.JSONDecodeError:
            return Datagram(command="error", content="invalid format")
    
    # helper classmethods to create datagrams
    @classmethod
    def msg(cls, from_user, to_user, content):
        return cls(command="msg", from_user=from_user, to_user=to_user, content=content)

    @classmethod
    def add(cls, contact):
        return cls(command="add", contact=contact)

    @classmethod
    def remove(cls, contact):
        return cls(command="remove", contact=contact)

    @classmethod
    def list_contacts(cls):
        return cls(command="list_contacts")

    @classmethod
    def contacts_list(cls, content):
        return cls(command="contacts_list", content=content)
        
    @classmethod
    def ack(cls, content):
        return cls(command="ack", content=content)

    @classmethod
    def error(cls, content):
        return cls(command="error", content=content)

    @classmethod
    def request_username(cls):
        return cls(command="request_username")

    @classmethod
    def login(cls, username):
        return cls(command="login", content=username)

    @classmethod
    def login_ok(cls, content):
        return cls(command="login_ok", content=content)

    @classmethod
    def quit(cls):
        return cls(command="quit")

    @classmethod
    # register in server user's public key in server
    def register_key(cls, public_key_b64):
        return cls(command="register_key", content=public_key_b64) 

    @classmethod
    # request to server another user's public key
    def request_session(cls, username):
        return cls(command="request_session", to_user=username)

    @classmethod
    # server's response to public key request
    def session_response(cls, username, certificate):
        return cls(command="session_response", from_user=username, content=certificate)

    @classmethod
    # receiving client's session has expired with sending client, tell server to inform him 
    def no_session_inform(cls, username):
        return cls(command="no_session_inform", to_user=username)

    @classmethod
    # receiving client's session has expired with sending client, server informs sender
    def no_session(cls, username):
        return cls(command="no_session", from_user=username)

    @classmethod
    def info(cls, content):
        return cls(command="info", content=content)

    @classmethod
    def send_session_ephemeral(cls, username, payload):
        return cls(command="send_session_ephemeral", to_user=username, content=payload)

    @classmethod
    def session_ephemeral(cls, payload):
        return cls(command="session_ephemeral", content=payload)
    
    @classmethod
    def add_group(cls, group_name):
        return cls(command="add_group", content=group_name)

    @classmethod
    def group_invite(cls, to_user, payload):
        return cls(command="group_invite", to_user=to_user  ,content=payload)

    @classmethod
    def group_invite_deliver(cls, from_user, payload):
        return cls(command="group_invite_deliver", from_user=from_user  ,content=payload)

    @classmethod
    def accept_invite(cls, group_name):
        return cls(command="accept_invite", content=group_name)

    @classmethod
    def group_msg(cls, sending_payload, content):
        return cls(command="group_msg", from_user=sending_payload, content=content)

    @classmethod
    def leave_group(cls, group_name):
        return cls(command="leave_group", content=group_name)

    @classmethod
    def ack_group(cls, group_name):
        return cls(command="ack_group", content=group_name)
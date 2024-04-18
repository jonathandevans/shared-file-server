from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol.login import verify_certificate
import base64
import json
import os

def write_notifs(notifications):
    try:
        if not os.path.exists("assets/notifs"):
            os.mkdir("assets/notifs")
        
        # Get the notifications from the header
        for user in notifications.keys():
            # Hash the user
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(user.encode())
            user_hash = hash.finalize()
            user_hash = base64.urlsafe_b64encode(user_hash).decode()
            
            if not os.path.exists(f"assets/notifs/{user_hash})"):
                with open(f"assets/notifs/{user_hash}", "wb") as f:
                    f.write(len(json.dumps(notifications[user])).to_bytes(4, "big"))
                    f.write(json.dumps(notifications[user]).encode())
            else:
                with open(f"assets/notifs/{user_hash}", "ab") as f:
                    f.write(len(json.dumps(notifications[user])).to_bytes(4, "big"))
                    f.write(json.dumps(notifications[user]).encode())
    except Exception as e:
        print(e)
        raise Exception("Failed to store notifications")

def request_notifs(client_socket, header):
    try:
        email = header["email"]
        hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash.update(email.encode())
        email_hash = hash.finalize()
        email_hash = base64.urlsafe_b64encode(email_hash).decode()
        
        if os.path.exists(f"assets/notifs/{email_hash}"):
            with open(f"assets/notifs/{email_hash}", "rb") as f:
                response = f"""{{
                    status: success
                    content-length: {os.path.getsize(f"assets/notifs/{email_hash}")}
                }}"""
                client_socket.sendall(len(response).to_bytes(4, "big"))
                client_socket.sendall(response.encode())
                client_socket.sendall(f.read())
                os.remove(f"assets/notifs/{email_hash}")
        else:
            response = f"""{{
                status: success
                content-length: 0
            }}"""
            client_socket.sendall(len(response).to_bytes(4, "big"))
            client_socket.sendall(response.encode())
    except Exception as e:
        print(e)
        response = f"""{{
            status: error
            message: Failed to retrieve notifications
        }}"""
        client_socket.sendall(len(response).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise Exception("Failed to retrieve notifications")
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol.connect import open_connection, send_header, parse_header
from protocol.share import symmetric_key_lookup
import base64
import json

def check_access(public_key, private_key, email, access_token, server_address, server_port, file_info):
    """
    Check if the user has access to a file. This function will send a request to the server
    
    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The file information
        
    Returns:
        bool: True if the user has access to the file, False otherwise
    """
    try:
        # Send the check-access request to the server
        try:
            remote_file = file_info["remote-file"]
            remote_acl = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            nonce = file_info["acl-nonce"]

            request = f"""{{
                type: check-access
                public-key: {base64.urlsafe_b64encode(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode()}
                email: {email}
                access-token: {access_token}
                file-name: {remote_file}
                acl-name: {remote_acl}
                acl-symmetric-key: {acl_symmetric_key}
                acl-nonce: {nonce}
            }}"""
            
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request)
        except Exception as e:
            raise Exception("Failed to create check-access request")
        
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        return True
    except Exception as e:
        return False

def parse_notifications(notifications, public_key, private_key, email, access_token, server_address, server_port):
    """Parse the notifications from the server and update the files.json file.

    Args:
        notifications (list): The list of notifications from the server
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server

    Raises:
        Exception: If the notifications cannot be parsed, an error message is raised
    """
    try:
        with open("assets/files.json", "r") as f:
            files = json.load(f)
        
        for notification in notifications:
            try:
                if notification["type"] == "revoke-access":
                    if notification["remote-file"] in files.keys():    
                        if not check_access(public_key, private_key, email, access_token, server_address, server_port, files[notification["remote-file"]]):
                            files.pop(notification["remote-file"])
                            with open("assets/files.json", "w") as f:
                                json.dump(files, f)
                                
                elif notification["type"] == "grant-access":                    
                    # Decrypt the symmetric key
                    symmetric_key = private_key.decrypt(
                        base64.urlsafe_b64decode(notification["encrypted-symmetric-key"]),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    # Decrypt the content using the symmetric key and nonce 
                    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(base64.urlsafe_b64decode(notification["nonce"])), backend=default_backend())
                    decryptor = cipher.decryptor()
                    content = decryptor.update(base64.urlsafe_b64decode(notification["encrypted-content"])) + decryptor.finalize()
                    file_info = json.loads(base64.urlsafe_b64decode(content).decode())
                    
                    if check_access(public_key, private_key, email, access_token, server_address, server_port, file_info):
                        files[file_info["remote-file"]] = file_info
                        with open("assets/files.json", "w") as f:
                            json.dump(files, f)
                            
                elif notification["type"] == "new-access":
                    symmetric_key = private_key.decrypt(
                        base64.urlsafe_b64decode(notification["encrypted-symmetric-key"]),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(base64.urlsafe_b64decode(notification["nonce"])), backend=default_backend())
                    decryptor = cipher.decryptor()
                    content = decryptor.update(base64.urlsafe_b64decode(notification["encrypted-content"])) + decryptor.finalize()
                    content = json.loads(base64.urlsafe_b64decode(content).decode())
                    
                    if content["email-hash"] not in files[content["remote-file"]]["users"].keys():
                        files[content["remote-file"]]["users"][content["email-hash"]] = content["email"]
                        with open("assets/files.json", "w") as f:
                            json.dump(files, f)
                            
                elif notification["type"] == "replace":
                    symmetric_key = private_key.decrypt(
                        base64.urlsafe_b64decode(notification["encrypted-symmetric-key"]),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(base64.urlsafe_b64decode(notification["nonce"])), backend=default_backend())
                    decryptor = cipher.decryptor()
                    content = decryptor.update(base64.urlsafe_b64decode(notification["encrypted-content"])) + decryptor.finalize()
                    content = json.loads(content.decode())
                    
                    symmetric_key = symmetric_key_lookup(public_key, private_key, email, access_token, server_address, server_port, files[content["remote-file"]])
                    # Hash the symmetric key comparing it to the sent symmetric key
                    symmetric_key_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    symmetric_key_hash.update(symmetric_key)
                    symmetric_key_hash.update(base64.urlsafe_b64decode(content["symmetric-key-nonce"]))
                    symmetric_key_hash = symmetric_key_hash.finalize()
                    if symmetric_key_hash == base64.urlsafe_b64decode(content["symmetric-key-hash"]):
                        files[content["remote-file"]]["hash"] = content["file-hash"]
                        files[content["remote-file"]]["filesize"] = content["file-size"]
                        files[content["remote-file"]]["updated"] = content["updated"]
                        with open("assets/files.json", "w") as f:
                            json.dump(files, f)
                        
            except Exception as e:
                continue
    except Exception as e:
        raise Exception("Failed to parse notifications")

def request_notifs(public_key, private_key, email, access_token, server_address, server_port):
    """Request notifications from the server. This function will send a request to the server
    to get the notifications for the user and save them to a file.

    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
    """
    try:
        # Send the request to the server
        try:
            request = f"""{{
                type: get-notifications
                public-key: {base64.urlsafe_b64encode(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode()}
                email: {email}
                access-token: {access_token}
            }}"""
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request)
        except Exception as e:
            raise Exception("Failed to create get-notifications request")
        
        # Check if request was successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        try:
            content_size = int(header["content-length"])
            
            notifications = []
            while content_size > 0:
                size = int.from_bytes(conn.recv(4), "big")
                if not size:
                    break
                notification = conn.recv(size)
                notifications.append(json.loads(notification.decode()))
                content_size -= (size + 4)
                
            parse_notifications(notifications, public_key, private_key, email, access_token, server_address, server_port)
        except Exception as e:
            raise Exception("Failed to parse notifications")
    except Exception as e:
        print(f"Failed to get notifications: {e}")
        input("Press enter to continue")

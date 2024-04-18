from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol.header import parse_header
from protocol.notif import write_notifs
import base64
import json
import os

def get_access(client_socket, header):
    try:
        try:
            # Check if the acl blob exists
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        try:
            # Decrypt the acl blob
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        try:
            # Check if the filename corresponds to the acl hashed filename
            acl_file_hash = acl["file-name-hash"]
            filename = header["file-name"]
            nonce = base64.urlsafe_b64decode(acl["nonce"])
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(filename.encode())
            hash.update(nonce)
            file_hash = hash.finalize()
            file_hash = base64.urlsafe_b64encode(file_hash).decode()
            
            if acl_file_hash != file_hash:
                raise Exception("Filename does not match acl")
        except Exception as e:
            raise Exception("Failed to verify filename in acl")
        
        try:
            # Check if the user is in the acl
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            email_hash = hash.finalize()
            email_hash = base64.urlsafe_b64encode(email_hash).decode()
            
            if email_hash not in acl.keys():
                raise Exception("User not in acl")
        except Exception as e:
            raise Exception("Failed to verify user in acl")
        
        try:
            # Check if the file blob exists
            if not os.path.exists(f"assets/blobs/{filename}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find file blob")
        
        try:
            permissions = {}
            for key in acl:
                # first check if the acl[key] is a dictionary
                if isinstance(acl[key], dict):
                    # then check if the dictionary has the key "permissions"
                    if "permissions" in acl[key]:
                        permissions[key] = acl[key]["permissions"]
        except Exception as e:
            raise Exception("Failed to get permissions")
        
        response = f"""{{
            status: success
            access-list: {base64.urlsafe_b64encode(json.dumps(permissions).encode()).decode()}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:        
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e

def check_access(client_socket, header):
    try:
        try:
            # Check if the acl blob exists
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        try:
            # Decrypt the acl blob
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        try:
            # Check if the filename corresponds to the acl hashed filename
            acl_file_hash = acl["file-name-hash"]
            filename = header["file-name"]
            nonce = base64.urlsafe_b64decode(acl["nonce"])
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(filename.encode())
            hash.update(nonce)
            file_hash = hash.finalize()
            file_hash = base64.urlsafe_b64encode(file_hash).decode()
            
            if acl_file_hash != file_hash:
                raise Exception("Filename does not match acl")
        except Exception as e:
            raise Exception("Failed to verify filename in acl")
        
        try:
            # Check if the user is in the acl
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            email_hash = hash.finalize()
            email_hash = base64.urlsafe_b64encode(email_hash).decode()
            if email_hash not in acl:
                raise Exception("User not in acl")
        except Exception as e:
            raise Exception("Failed to verify user in acl")
        
        response = f"""{{
            status: success
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e

def user_lookup(client_socket, header):
    try:
        try:
            # Check if the users.csv file exists
            if not os.path.exists("assets/users.csv"):
                raise Exception("Users file does not exist")
        except Exception as e:
            raise Exception("Failed to find users file")
        
        try:
            # Check if the email is in the users.csv file
            email = header["shared-email"]
            cert_file = None
            with open("assets/users.csv", "r") as f:
                for line in f:
                    if email == line.split(",")[0]:
                        public_key = line.split(",")[1].strip()
                        cert_file = line.split(",")[2].strip()
                        break
                else:
                    raise Exception("Email not found")
        except Exception as e:
            raise Exception("Failed to find email in users file")
        
        with open(f"assets/store/{cert_file}", "rb") as f:
            cert = base64.urlsafe_b64encode(f.read()).decode()
        response = f"""{{
            status: success
            public-key: {public_key}
            certificate: {cert}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e
    
def symmetric_key_lookup(client_socket, header):
    try:
        try:
            # Check if the acl blob exists
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        try:
            # Decrypt the acl blob
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        try:
            # Check if the filename corresponds to the acl hashed filename
            acl_file_hash = acl["file-name-hash"]
            filename = header["file-name"]
            nonce = base64.urlsafe_b64decode(acl["nonce"])
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(filename.encode())
            hash.update(nonce)
            file_hash = hash.finalize()
            file_hash = base64.urlsafe_b64encode(file_hash).decode()
            
            if acl_file_hash != file_hash:
                raise Exception("Filename does not match acl")
        except Exception as e:
            raise Exception("Failed to verify filename in acl")
        
        try:
            # Check if the user is in the acl
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            email_hash = hash.finalize()
            email_hash = base64.urlsafe_b64encode(email_hash).decode()
            
            if email_hash not in acl.keys():
                raise Exception("User not in acl")
        except Exception as e:
            raise Exception("Failed to verify user in acl")
        
        try:
            # Check if the file blob exists
            if not os.path.exists(f"assets/blobs/{filename}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find file blob")
        
        # Send the encrypted symmetric key to the client
        try:
            symmetric_key = acl[email_hash]["symmetric-key"]
            response = f"""{{
                status: success
                encrypted-symmetric-key: {symmetric_key}
            }}
            """
            client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
            client_socket.sendall(response.encode())
        except Exception as e:
            raise Exception("Failed to send symmetric key")
    except Exception as e:
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e
    
def grant_access(client_socket, header):
    try:
        try:
            # Check if the acl blob exists
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        try:
            # Decrypt the acl blob
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        try:
            # Check if the filename corresponds to the acl hashed filename
            acl_file_hash = acl["file-name-hash"]
            filename = header["file-name"]
            nonce = base64.urlsafe_b64decode(acl["nonce"])
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(filename.encode())
            hash.update(nonce)
            file_hash = hash.finalize()
            file_hash = base64.urlsafe_b64encode(file_hash).decode()
            
            if acl_file_hash != file_hash:
                raise Exception("Filename does not match acl")
        except Exception as e:
            raise Exception("Failed to verify filename in acl")
        
        try:
            # Check if the user is in the acl and has permissions
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            email_hash = hash.finalize()
            email_hash = base64.urlsafe_b64encode(email_hash).decode()
            
            permissions = int(header["permissions"])
            if email_hash not in acl:
                raise Exception("User not in acl")
            if acl[email_hash]["permissions"] != 0 and acl[email_hash]["permissions"] != 1:
                raise Exception("User does not have permissions")
            if permissions <= acl[email_hash]["permissions"]:
                raise Exception("User does not have permissions")
        except Exception as e:
            raise Exception("Invalid permissions")
        
        try:
            # Check if the file blob exists
            if not os.path.exists(f"assets/blobs/{filename}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find file blob")
        
        try:
            # Check if the user is already in the acl
            user_email = header["shared-email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(user_email.encode())
            hash.update(nonce)
            user_email_hash = hash.finalize()
            user_email_hash = base64.urlsafe_b64encode(user_email_hash).decode()
            
            if user_email_hash in acl:
                raise Exception("User already in acl")
        except Exception as e:
            raise Exception("User already in acl")
        
        # Add the user to the acl
        try:
            acl[user_email_hash] = {
                "permissions": permissions,
                "symmetric-key": header["encrypted-symmetric-key"]
            }
        except Exception as e:
            raise Exception("Failed to add user to acl")
        
        # Encrypt the acl and write it to the acl blob
        try:
            acl = json.dumps(acl)
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            acl = encryptor.update(acl.encode()) + encryptor.finalize()
            with open(f"assets/blobs/{acl_name}", "wb") as f:
                f.write(acl)
        except Exception as e:
            raise Exception("Failed to encrypt acl blob")
        
        response = f"""{{
            status: success
            email-hash: {user_email_hash}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        
        header = parse_header(client_socket)
        if header["type"] == "notifications":
            notifications = json.loads(base64.urlsafe_b64decode(header["notifications"].encode()).decode())
            write_notifs(notifications)
            
        response = f"""{{
            status: success
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e

def revoke_access(client_socket, header):
    try:
        try:
            # Check if the acl blob exists
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        try:
            # Decrypt the acl blob
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        try:
            # Check if the filename corresponds to the acl hashed filename
            acl_file_hash = acl["file-name-hash"]
            filename = header["file-name"]
            nonce = base64.urlsafe_b64decode(acl["nonce"])
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(filename.encode())
            hash.update(nonce)
            file_hash = hash.finalize()
            file_hash = base64.urlsafe_b64encode(file_hash).decode()
            
            if acl_file_hash != file_hash:
                raise Exception("Filename does not match acl")
        except Exception as e:
            raise Exception("Failed to verify filename in acl")
        
        try:
            # Check if the user is in the acl and has permissions
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            email_hash = hash.finalize()
            email_hash = base64.urlsafe_b64encode(email_hash).decode()
            
            shared_email = header["shared-email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(shared_email.encode())
            hash.update(nonce)
            shared_email_hash = hash.finalize()
            shared_email_hash = base64.urlsafe_b64encode(shared_email_hash).decode()
            
            if email_hash not in acl:
                raise Exception("User not in acl")
            if shared_email_hash not in acl:
                raise Exception("User not in acl")
            if acl[email_hash]["permissions"] != 0 and acl[email_hash]["permissions"] != 1:
                raise Exception("User does not have permissions")
            if acl[shared_email_hash]["permissions"] <= acl[email_hash]["permissions"]:
                raise Exception("User does not have permissions")
        except Exception as e:
            raise Exception("Invalid permissions")
        
        # Remove the user from the acl
        try:
            del acl[shared_email_hash]
        except Exception as e:
            raise Exception("Failed to remove user from acl")
        
        # Encrypt the acl and write it to the acl blob
        try:
            acl = json.dumps(acl)
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            acl = encryptor.update(acl.encode()) + encryptor.finalize()
            with open(f"assets/blobs/{acl_name}", "wb") as f:
                f.write(acl)
        except Exception as e:
            raise Exception("Failed to encrypt acl blob")
        
        # Get the notifications from the header
        notification = json.loads(base64.urlsafe_b64decode(header["notification"].encode()).decode())
        notification = {
            shared_email: notification
        }
        write_notifs(notification)
        
        response = f"""{{
            status: success
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e

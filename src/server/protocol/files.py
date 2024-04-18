from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol.notif import write_notifs
import base64
import json
import os
import secrets

def upload(client_socket, header):
    """Upload a file to the server and store it in the assets/blobs directory.
    Create an access control list for the file and store it in the assets/blobs directory.
    Send a response to the client with the status of the upload.
    
    Args:
        client_socket (socket): The client's socket
        header (dict): The header dictionary from the client
    
    Raises:
        Exception: If any part of the upload process fails, an error message is raised
    """
    try:
        if not os.path.exists("assets/blobs"):
            os.mkdir("assets/blobs")
            
        if not os.path.exists("assets/notifs"):
            os.mkdir("assets/notifs")
            
        if not os.path.exists("assets/temp"):
            os.mkdir("assets/temp")
        
        # Store the encrypted blob
        try:
            filename = os.urandom(32).hex()
            while os.path.exists(f"assets/blobs/{filename}"):
                filename = os.urandom(32).hex()
            content_length = int(header["content-length"])
            with open(f"assets/blobs/{filename}", "wb") as f:
                while content_length > 0:
                    data = client_socket.recv(min(4096, content_length))
                    f.write(data)
                    content_length -= len(data)
        except Exception as e:
            raise Exception("Failed to store encrypted blob")
        
        # Verify the file hash
        try:
            remote_hash = header["file-hash"]
            remaining = os.path.getsize(f"assets/blobs/{filename}")
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            with open(f"assets/blobs/{filename}", "rb") as f:
                while remaining > 0:
                    data = f.read(min(4096, remaining))
                    hash.update(data)
                    remaining -= len(data)
            local_hash = hash.finalize()
            if remote_hash != base64.urlsafe_b64encode(local_hash).decode():
                raise Exception("File hash does not match")
        except Exception as e:
            raise Exception("Failed to verify file hash")
        
        # Create the acl
        try:
            nonce = secrets.token_bytes(32)            
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(filename.encode())
            hash.update(nonce)
            file_hash = hash.finalize()
            file_hash = base64.urlsafe_b64encode(file_hash).decode()
            
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(header["email"].encode())
            hash.update(nonce)
            user_hash = hash.finalize()
            user_hash = base64.urlsafe_b64encode(user_hash).decode()
            
            acl = {
                "nonce": base64.urlsafe_b64encode(nonce).decode(),
                "file-nonce": header["nonce"],
                "file-name-hash": file_hash,
                user_hash: {
                    "symmetric-key": header["encrypted-symmetric-key"],
                    "permissions": 0
                },
            }
        except Exception as e:
            raise Exception("Failed to create access control list")
        
        # Store the acl
        try:
            acl_name = os.urandom(32).hex()
            acl_nonce = secrets.token_bytes(16)
            while os.path.exists(f"assets/blobs/{acl_name}"):
                acl_name = os.urandom(32).hex()
            with open(f"assets/blobs/{acl_name}", "wb") as f:
                # Store the acl as json and Encrypt the acl with a symmetric key
                json_acl = json.dumps(acl).encode()
                # Generate a symmetric key
                key = secrets.token_bytes(32)
                # Encrypt the acl
                cipher = Cipher(algorithms.AES(key), modes.CTR(acl_nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(json_acl) + encryptor.finalize()
                f.write(ciphertext)
        except Exception as e:
            raise Exception("Failed to store access control list")
        
        response = f"""{{
            status: success
            acl-name: {acl_name}
            file-name: {filename}
            acl-symmetric-key: {base64.urlsafe_b64encode(key).decode()}
            acl-nonce: {base64.urlsafe_b64encode(acl_nonce).decode()}
            hashed-email: {user_hash}
        }}
        """
        response_length = len(response.encode())
        client_socket.sendall(response_length.to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:
        os.remove(f"assets/blobs/{filename}")
        os.remove(f"assets/blobs/{acl_name}")
        
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e

def download(client_socket, header):
    """Download a file from the server and send it to the client.
    
    Args:
        client_socket (socket): The client's socket
        header (dict): The header dictionary from the client
        
    Raises:
        Exception: If any part of the download process fails, an error message is raised
    """
    try:
        # Check if the acl blob exists
        try:
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        # Decrypt the acl blob
        try:
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        # Check if the filename corresponds to the acl hashed filename
        try:
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
        
        # Check if the user is in the acl
        try:
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            user_hash = hash.finalize()
            user_hash = base64.urlsafe_b64encode(user_hash).decode()
            
            if user_hash not in acl.keys():
                raise Exception("User not in acl")
        except Exception as e:
            raise Exception("Failed to verify user in acl")
        
        # Check if the file blob exists
        try:
            if not os.path.exists(f"assets/blobs/{filename}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find file blob")
        
        response = f"""{{
            status: success
            encrypted-symmetric-key: {acl[user_hash]["symmetric-key"]}
            nonce: {acl["file-nonce"]}
            content-length: {os.path.getsize(f"assets/blobs/{filename}")}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        remaining = os.path.getsize(f"assets/blobs/{filename}")
        with open(f"assets/blobs/{filename}", "rb") as f:
            while remaining > 0:
                chunk = f.read(min(remaining, 4096))
                client_socket.sendall(chunk)
                remaining -= len(chunk)
    except Exception as e:        
        response = f"""{{
            status: error
            message: {e}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e

def delete(client_socket, header):
    """Delete a file from the server and send revoke notifications to all users in the acl.
    
    Args:
        client_socket (socket): The client's socket
        header (dict): The header dictionary from the client
        
    Raises:
        Exception: If any part of the delete process fails, an error message is raised
    """
    try:
        # Check if the acl blob exists
        try:
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        # Decrypt the acl blob
        try:
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        # Check if the filename corresponds to the acl hashed filename
        try:
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
        
        # Check if the user is in the acl and has permissions to delete
        try:
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            user_hash = hash.finalize()
            user_hash = base64.urlsafe_b64encode(user_hash).decode()
            
            if user_hash not in acl:
                raise Exception("User not in acl")
            if acl[user_hash]["permissions"] != 0:
                raise Exception("User does not have permissions to delete")
        except Exception as e:
            raise e
        
        # Check if the file blob exists
        try:
            if not os.path.exists(f"assets/blobs/{filename}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find file blob")
        
        try:
            # Get the notifications from the header
            notifications = json.loads(base64.urlsafe_b64decode(header["notifications"]).decode())
            print(notifications)
            write_notifs(notifications)
        except Exception as e:
            raise Exception("Failed to store notifications")
                        
        # Delete the file blob
        os.remove(f"assets/blobs/{filename}")
        os.remove(f"assets/blobs/{acl_name}")
        
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
    
def replace(client_socket, header):
    try:
        # Check if the acl blob exists
        try:
            acl_name = header["acl-name"]
            if not os.path.exists(f"assets/blobs/{acl_name}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find acl blob")
        
        # Decrypt the acl blob
        try:
            acl_symmetric_key = base64.urlsafe_b64decode(header["acl-symmetric-key"])
            acl_nonce = base64.urlsafe_b64decode(header["acl-nonce"])
            cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(f"assets/blobs/{acl_name}", "rb") as f:
                acl = decryptor.update(f.read()) + decryptor.finalize()
            acl = json.loads(acl)
        except Exception as e:
            raise Exception("Failed to decrypt acl blob")
        
        # Check if the filename corresponds to the acl hashed filename
        try:
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
        
        # Check if the user is in the acl and has permissions to replace
        try:
            email = header["email"]
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(email.encode())
            hash.update(nonce)
            user_hash = hash.finalize()
            user_hash = base64.urlsafe_b64encode(user_hash).decode()
            
            if user_hash not in acl:
                raise Exception("User not in acl")
            if acl[user_hash]["permissions"] != 0 and acl[user_hash]["permissions"] != 1:
                raise Exception("User does not have permissions to replace")
        except Exception as e:
            raise e
        
        # Check if the file blob exists
        try:
            if not os.path.exists(f"assets/blobs/{filename}"):
                raise Exception("File does not exist")
        except Exception as e:
            raise Exception("Failed to find file blob")
        
        # Store the encrypted blob
        try:
            if not os.path.exists("assets/temp"):
                os.mkdir("assets/temp")
            
            content_length = int(header["content-length"])
            with open(f"assets/temp/{filename}", "wb") as f:
                while content_length > 0:
                    data = client_socket.recv(min(4096, content_length))
                    f.write(data)
                    content_length -= len(data)
        except Exception as e:
            raise Exception("Failed to store encrypted blob")
        
        # Verify the file hash
        try:
            remote_hash = header["file-hash"]
            remaining = os.path.getsize(f"assets/temp/{filename}")
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            with open(f"assets/temp/{filename}", "rb") as f:
                while remaining > 0:
                    data = f.read(min(4096, remaining))
                    hash.update(data)
                    remaining -= len(data)
            local_hash = hash.finalize()
            if remote_hash != base64.urlsafe_b64encode(local_hash).decode():
                raise Exception("File hash does not match")
            
            # Move the file to the blobs directory
            os.rename(f"assets/temp/{filename}", f"assets/blobs/{filename}")
        except Exception as e:
            print(e)
            raise Exception("Failed to verify file hash")
        finally:
            if os.path.exists(f"assets/temp/{filename}"):
                os.remove(f"assets/temp/{filename}")
        
        # Update the acl nonce
        try:
            acl["file-nonce"] = header["nonce"]
        except Exception as e:
            raise Exception("Failed to update acl nonce")
        
        # Re-encrypt the acl blob using the same symmetric key and nonce
        try:
            with open(f"assets/blobs/{acl_name}", "wb") as f:
                # Store the acl as json and Encrypt the acl with a symmetric key
                json_acl = json.dumps(acl).encode()
                cipher = Cipher(algorithms.AES(acl_symmetric_key), modes.CTR(acl_nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(json_acl) + encryptor.finalize()
                f.write(ciphertext)
        except Exception as e:
            raise Exception("Failed to re-encrypt acl blob")
        
        try:
            # Get the notifications from the header
            notifications = json.loads(base64.urlsafe_b64decode(header["notifications"]).decode())
            write_notifs(notifications)
        except Exception as e:
            raise Exception("Failed to store notifications")
        
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
        
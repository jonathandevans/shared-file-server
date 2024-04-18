from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol.connect import open_connection, parse_header, send_header, generate_symmetric_key
from protocol.share import symmetric_key_lookup, user_lookup, get_access
import base64
import datetime
import json
import os
import secrets

def encrypt_file(symmetric_key, filepath):
    """Encrypts a file using AES-CTR and a symmetric key stored in the temp directory.

    Args:
        symmetric_key (bytes): The symmetric key to encrypt the file with
        filepath (str): The path to the file to encrypt

    Returns:
        tuple: A tuple containing the path to the encrypted file and the nonce used to encrypt the file
    """
    # Generate a random filename
    random_filename = os.urandom(16).hex()
    while os.path.exists(f"assets/temp/{random_filename}.enc"):
        random_filename = os.urandom(16).hex()
    
    # Stream over the file and encrypt it store it in a temporary file
    nonce = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    remaining = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        with open(f"assets/temp/{random_filename}.enc", "wb") as out:
            while remaining > 0:
                chunk = f.read(min(remaining, 4096))
                remaining -= len(chunk)
                out.write(encryptor.update(chunk))
            out.write(encryptor.finalize())
    
    return f"assets/temp/{random_filename}.enc", nonce

def hash_file(filepath):
    """Hashes a file using SHA-256.

    Args:
        filepath (str): The path to the file to hash

    Returns:
        bytes: The hash of the file
    """
    hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    remaining = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        while remaining > 0:
            chunk = f.read(min(remaining, 4096))
            remaining -= len(chunk)
            hash.update(chunk)
            
    return hash.finalize()

def save_uploaded_file(remote_file, remote_acl, acl_symmetric_key, nonce, owner, filename, filesize, file_hash, hash_email, date):
    """Saves the information about an uploaded file to the files.json file.

    Args:
        remote_file (str): The name of the file on the server
        remote_acl (str): The name of the acl file on the server
        acl_symmetric_key (str): The symmetric key of the acl file in base64
        nonce (str): The nonce used to encrypt the acl file in base64
        owner (str): The email of the owner of the file
        filename (str): The name of the file
        filesize (int): The size of the file
        file_hash (str): The hash of the file in base64
        hash_email (str): The hashed email of the owner
        date (str): The date the file was uploaded

    Raises:
        Exception: If the file information cannot be stored
    """
    try:
        # Check if the files.json file exists
        if not os.path.exists("assets/files.json"):
            with open("assets/files.json", "w") as f:
                f.write("{}")
        
        # Read and parse the JSON file
        try:
            with open("assets/files.json", "r") as f:
                files = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON file: {e}")
            raise Exception("Failed to parse files.json")
        
        # Append the new file information
        files[remote_file] = {
            "remote-file": remote_file,
            "remote-acl": remote_acl,
            "acl-nonce": nonce,
            "acl-symmetric-key": acl_symmetric_key,
            "owner": owner,
            "filename": filename,
            "filesize": filesize,
            "updated": date,
            "hash": file_hash,
            "users": {
                hash_email: owner
            }
        }
        
        # Write the updated JSON back to the file
        with open("assets/files.json", "w") as f:
            json.dump(files, f, indent=4)
    except Exception as e:
        raise Exception("Failed to store file information")

def upload(public_key, private_key, email, access_token, server_address, server_port, filepath):
    """Uploads a file to the server.
    
    Args:
        public_key (RSAPublicKey): The public key of the client 
        private_key (RSAPrivateKey): The private key of the client
        email (str): The email of the user
        access_token (str): The access token of the user
        server_address (str): The address of the server
        server_port (int): The port of the server
        filepath (str): The path to the file to upload
    """
    try:
        # Make the assets/temp directory if it doesn't exist
        if not os.path.exists("assets/temp"):
            os.mkdir("assets/temp")
        
        # Check if the file exists whether relative or absolute path
        try:
            if not os.path.isabs(filepath):
                # When running the program using the script, the directory the user 
                # thinks they are in is actually the root directory
                # So we need to prepend the path with ../../
                filepath = "../../" + filepath
            if not os.path.exists(filepath):
                raise Exception("File does not exist")
        except Exception as e:
            raise e
    
        # Get the file information
        try:    
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
        except Exception as e:
            raise Exception("Failed to get file information")
        
        # Encrypt the file and generate a hash
        try:
            symmetric_key, encrypted_symmetric_key = generate_symmetric_key(public_key)
            encrypted_file, nonce = encrypt_file(symmetric_key, filepath)
            hash = hash_file(filepath)
            encrypted_hash = hash_file(encrypted_file)
        except Exception as e:
            raise Exception("Failed to encrypt file")
        
        # Send the upload request
        try:
            conn = open_connection(server_address, server_port)
            
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            
            request = f"""{{
                type: upload
                public-key: {public_key_base64}
                access-token: {access_token}
                email: {email}
                file-hash: {base64.urlsafe_b64encode(encrypted_hash).decode()}
                nonce: {base64.urlsafe_b64encode(nonce).decode()}
                encrypted-symmetric-key: {base64.urlsafe_b64encode(encrypted_symmetric_key).decode()}
                content-length: {os.path.getsize(encrypted_file)}
            }}"""
            
            send_header(conn, private_key, request)
            # Stream the file to the server
            with open(encrypted_file, "rb") as f:
                remaining = os.path.getsize(encrypted_file)
                while remaining > 0:
                    chunk = f.read(min(remaining, 4096))
                    remaining -= len(chunk)
                    conn.sendall(chunk)
        except Exception as e:
            raise Exception("Failed to send upload request")
        
        # Check the response from was successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        # Store the uploaded file information
        try:
            remote_file = header["file-name"]
            remote_acl = header["acl-name"]
            acl_symmetric_key = header["acl-symmetric-key"]
            acl_nonce = header["acl-nonce"]
            hashed_email = header["hashed-email"]
        except Exception as e:
            raise Exception("Failed to parse response")
        save_uploaded_file(remote_file, remote_acl, acl_symmetric_key, acl_nonce, email, filename, filesize, base64.urlsafe_b64encode(hash).decode(), hashed_email, datetime.datetime.now().strftime("%Y-%m-%d"))
        
        print("File uploaded successfully")
    except Exception as e:        
        print(f"Failed to upload file: {e}")
    finally:
        input("Press enter to continue...")
        # Clean up the temporary directory
        for file in os.listdir("assets/temp"):
            os.remove(f"assets/temp/{file}")
        
def download(public_key, private_key, email, access_token, server_address, server_port, file_info):
    """Downloads a file from the server
    
    Args:
        public_key (RSAPublicKey): The public key of the client
        private_key (RSAPrivateKey): The private key of the client
        email (str): The email of the user
        access_token (str): The access token of the user
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file to download
    """
    try:
        # Make the assets/temp directory if it doesn't exist
        if not os.path.exists("assets/temp"):
            os.mkdir("assets/temp")
        
        # Connect to the server and send the request
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            real_file_name = file_info["filename"]
            acl_nonce = file_info["acl-nonce"]
            
            request_header = f"""{{
                type: download
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                file-name: {file_name}
                acl-name: {acl_name}
                acl-nonce: {acl_nonce}
                acl-symmetric-key: {acl_symmetric_key}
            }}"""
            
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request_header)
        except Exception as e:
            raise Exception("Failed to connect to server")
        
        # Check the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        # Parse the response header
        try:
            encrypted_symmetric_key = header["encrypted-symmetric-key"]
            nonce = base64.urlsafe_b64decode(header["nonce"])
            content_length = int(header["content-length"])
        except Exception as e:
            raise Exception("Failed to parse response")
        
        # Download the encrypted file into a temporary file
        try:
            temp_file = f"assets/temp/{file_name}"
            with open(temp_file, "wb") as f:
                remaining = content_length
                while remaining > 0:
                    chunk = conn.recv(min(remaining, 4096))
                    f.write(chunk)
                    remaining -= len(chunk)
        except Exception as e:
            raise Exception("Failed to download file")
        
        # Decrypt the file
        try:
            symmetric_key = private_key.decrypt(
                base64.urlsafe_b64decode(encrypted_symmetric_key),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            
            # Check if the file already exists and if so, create a copy
            if os.path.exists(f"../../{real_file_name}"):
                copies = 1
                # Split the filename and extension
                filename, extension = os.path.splitext(real_file_name)
                while os.path.exists(f"../../{filename} ({copies}){extension}"):
                    copies += 1
                real_file_name = f"{filename} ({copies}){extension}"
            
            with open(f"../../{real_file_name}", "wb") as f:
                with open(temp_file, "rb") as temp:
                    remaining = os.path.getsize(temp_file)
                    while remaining > 0:
                        chunk = temp.read(min(remaining, 4096))
                        decrypted_chunk = decryptor.update(chunk)
                        f.write(decrypted_chunk)
                        remaining -= len(chunk)
                f.write(decryptor.finalize())
        except Exception as e:
            raise Exception("Failed to decrypt file")
        
        # Check the hash of the downloaded file is as expected
        local_hash = hash_file(f"../../{real_file_name}")
        if base64.urlsafe_b64encode(local_hash).decode() != file_info["hash"]:
            os.remove(f"../../{real_file_name}")
            raise Exception("File hash does not match")
            
        print("File downloaded successfully")
    except Exception as e:
        print(f"Failed to download file: {e}")
    finally:
        input("Press enter to continue...")
        # Clean up the temporary directory
        for file in os.listdir("assets/temp"):
            os.remove(f"assets/temp/{file}")
            
def delete(public_key, private_key, email, access_token, server_address, server_port, file_info):
    """Deletes a file from the server
    
    Args:
        public_key (RSAPublicKey): The public key of the client
        private_key (RSAPrivateKey): The private key of the client
        email (str): The email of the user
        access_token (str): The access token of the user
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file to delete
    """
    try:
        # Get the users who have access to the file
        try:
            users = get_access(public_key, private_key, email, access_token, server_address, server_port, file_info)
        except Exception as e:
            raise Exception("Failed to get access information")
        
        # Generate a dictionary of notifications to send
        # We use revoke notifications
        try:
            notifications = {}
            _users = []
            for user in users.keys():
                    if users[user] != 0:
                        _users.append(user)
            for user in _users:
                notif = {
                    "type": "revoke-access",
                    "remote-file": file_info["remote-file"],
                }
                notifications[user] = notif
            notifications = json.dumps(notifications)
        except Exception as e:
            raise Exception("Failed to generate notifications")
        
        # Connect to the server and send the request
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            acl_nonce = file_info["acl-nonce"]
            
            request_header = f"""{{
                type: delete
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                file-name: {file_name}
                acl-name: {acl_name}
                acl-nonce: {acl_nonce}
                acl-symmetric-key: {acl_symmetric_key}
                notifications: {base64.urlsafe_b64encode(notifications.encode()).decode()}
            }}"""
            
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request_header)
        except Exception as e:
            raise Exception("Failed to connect to server")
        
        # Check the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
    
        # Remove the file from the files.json file
        try:
            with open("assets/files.json", "r") as f:
                files = json.load(f)
            files.pop(file_name)
            with open("assets/files.json", "w") as f:
                json.dump(files, f, indent=4)
        except Exception as e:
            raise Exception("Failed to update local file information")
        
        print("File deleted successfully")
    except Exception as e:
        print(f"Failed to delete file: {e}")
    finally:
        input("Press enter to continue...")

def replace(public_key, private_key, email, access_token, server_address, server_port, file_info, filepath):
    """Replaces a file on the server
    
    Args:
        public_key (RSAPublicKey): The public key of the client
        private_key (RSAPrivateKey): The private key of the client
        email (str): The email of the user
        access_token (str): The access token of the user
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file to replace
        filepath (str): The path to the file to replace the current file with
    """
    try:
        # Make the assets/temp directory if it doesn't exist
        if not os.path.exists("assets/temp"):
            os.mkdir("assets/temp")
        
        # Check if the file exists whether relative or absolute path
        try:
            if not os.path.isabs(filepath):
                # When running the program using the script, the directory the user thinks they are in is actually the root directory
                # So we need to prepend the path with ../../
                filepath = "../../" + filepath
            if not os.path.exists(filepath):
                raise Exception("File does not exist")
            filesize = os.path.getsize(filepath)
        except Exception as e:
            raise Exception("Failed to get file information")
        
        # Get the existing symmetric key from the acl file
        symmetric_key = symmetric_key_lookup(public_key, private_key, email, access_token, server_address, server_port, file_info)
        # Encrypt the file and generate a hash
        try:
            encrypted_file, nonce = encrypt_file(symmetric_key, filepath)
            file_hash = hash_file(filepath)
            encrypted_hash = hash_file(encrypted_file)
        except Exception as e:
            raise Exception("Failed to encrypt file")
        
        # Hash the symmetric key with a random nonce
        try:
            symmetric_key_nonce = secrets.token_bytes(32)
            hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hash.update(symmetric_key)
            hash.update(symmetric_key_nonce)
            symmetric_key_hash = hash.finalize()
        except Exception as e:
            raise Exception("Failed to hash symmetric key")
        
        # Create notifications for the users who have access to the file
        try:
            users = get_access(public_key, private_key, email, access_token, server_address, server_port, file_info)
            users.pop(email)
            notifications = {}
            for user in users.keys():
                content = {
                    "remote-file": file_info["remote-file"],
                    "remote-acl": file_info["remote-acl"],
                    "acl-symmetric-key": file_info["acl-symmetric-key"],
                    "acl-nonce": file_info["acl-nonce"],
                    "file-hash": base64.urlsafe_b64encode(file_hash).decode(),
                    "file-size": filesize,
                    "updated": datetime.datetime.now().strftime("%Y-%m-%d"),
                    "symmetric-key-hash": base64.urlsafe_b64encode(symmetric_key_hash).decode(),
                    "symmetric-key-nonce": base64.urlsafe_b64encode(symmetric_key_nonce).decode(),
                }
                user_public_key = user_lookup(public_key, private_key, email, access_token, server_address, server_port, user)
                symmetric_key, encrypted_symmetric_key = generate_symmetric_key(user_public_key)
                nonce = secrets.token_bytes(16)
                # Encrypt the content with the user's symmetric key
                cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_content = encryptor.update(json.dumps(content).encode())
                encrypted_content += encryptor.finalize()
                # Convert the encrypted content to base64
                encrypted_content = base64.urlsafe_b64encode(encrypted_content).decode()
                notif = {
                    "type": "replace",
                    "encrypted-content": encrypted_content,
                    "encrypted-symmetric-key": base64.urlsafe_b64encode(encrypted_symmetric_key).decode(),
                    "nonce": base64.urlsafe_b64encode(nonce).decode(),
                }
                notifications[user] = notif
            notifications = json.dumps(notifications)
        except Exception as e:
            print(e)
            raise Exception("Failed to generate notifications")
        
        # Send the replace request
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            acl_nonce = file_info["acl-nonce"]
            
            request_header = f"""{{
                type: replace
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                file-name: {file_name}
                acl-name: {acl_name}
                acl-nonce: {acl_nonce}
                acl-symmetric-key: {acl_symmetric_key}
                file-hash: {base64.urlsafe_b64encode(encrypted_hash).decode()}
                nonce: {base64.urlsafe_b64encode(nonce).decode()}
                content-length: {os.path.getsize(encrypted_file)}
                notifications: {base64.urlsafe_b64encode(notifications.encode()).decode()}
            }}"""
            
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request_header)
            # Stream the file to the server
            with open(encrypted_file, "rb") as f:
                remaining = os.path.getsize(encrypted_file)
                while remaining > 0:
                    chunk = f.read(min(remaining, 4096))
                    remaining -= len(chunk)
                    conn.sendall(chunk)
        except Exception as e:
            raise Exception("Failed to send replace request")
        
        # Check the response from was successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        # Overwrite the local file information
        try:
            with open("assets/files.json", "r") as f:
                files = json.load(f)
            files[file_name]["hash"] = base64.urlsafe_b64encode(file_hash).decode()
            files[file_name]["filesize"] = filesize
            files[file_name]["updated"] = datetime.datetime.now().strftime("%Y-%m-%d")
            with open("assets/files.json", "w") as f:
                json.dump(files, f, indent=4)
        except Exception as e:
            raise Exception("Failed to update local file information")
        
        print("File replaced successfully")
    except Exception as e:
        print(f"Failed to replace file: {e}")
    finally:
        input("Press enter to continue...")
        # Clean up the temporary directory
        for file in os.listdir("assets/temp"):
            os.remove(f"assets/temp/{file}")
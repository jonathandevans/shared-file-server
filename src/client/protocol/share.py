from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from protocol.connect import open_connection, send_header, parse_header, generate_symmetric_key
import base64
import json
import secrets

def get_access(public_key, private_key, email, access_token, server_address, server_port, file_info):
    """Get the access list for a file.
    
    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file
        
    Returns:
        dict: The access list for the file
        
    Raises:
        Exception: If the access list cannot be retrieved, an error message is raised
    """
    try:        
        # Connect to the server and send the request header
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            acl_nonce = file_info["acl-nonce"]
            
            request_header = f"""{{
                type: get-access
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
        
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        _access_list = {}
        access_list = json.loads(base64.urlsafe_b64decode(header["access-list"]).decode())
        for user in access_list.keys():
            if user in file_info["users"].keys():
                _access_list[file_info["users"][user]] = access_list[user]
                
        # print(_access_list)
        # print(access_list)
                
        return _access_list
    except Exception as e:
        raise Exception("Failed to get access list")

def user_lookup(public_key, private_key, email, access_token, server_address, server_port, user_email):
    """Lookup a user's public key and certificate.
    
    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
        user_email (str): The email of the user to lookup
        
    Returns:
        RSAPublicKey: The user's public key
        
    Raises:
        Exception: If the user cannot be found, an error message is raised
    """
    try:
        # Create a request header to lookup the user
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            
            request_header = f"""{{
                type: user-lookup
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                shared-email: {user_email}
            }}"""
            
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request_header)
        except Exception as e:
            raise Exception("Failed to send content")
        
        # Check if the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        # Get the user's public key and certificate
        try:
            user_public_key = header["public-key"]
            user_public_key = base64.urlsafe_b64decode(user_public_key.encode())
            user_public_key = serialization.load_pem_public_key(
                user_public_key,
                backend=default_backend()
            )
        except Exception as e:
            raise e
        
        # Verify the user's certificate and that the email matches the certificate common name
        try:
            cert = base64.urlsafe_b64decode(header["certificate"].encode())
            # Read the top certificate in the chain
            cert = cert.split(b"-----END CERTIFICATE-----\n")[0] + b"-----END CERTIFICATE-----\n"
            cert = x509.load_pem_x509_certificate(cert, default_backend())
            
            # Verify the certificate using the ca-cert.pem
            with open("../ca-cert.pem", "rb") as f:
                ca_cert = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert, default_backend())
            ca_public_key = ca_cert.public_key()
            # This checks that the certificate's signature is valid and was created by the CA's private key
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            
            # Check if the email matches the certificate common name
            if user_email != cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value:
                raise Exception("Email does not match certificate")
            
            # Get the user's public key from the certificate
            public_key = cert.public_key()
            if public_key != user_public_key:
                raise Exception("Public key does not match certificate")
        except Exception as e:
            raise Exception("Failed to verify user certificate")
        
        return user_public_key
    except Exception as e:
        raise Exception("Failed to lookup user")

def symmetric_key_lookup(public_key, private_key, email, access_token, server_address, server_port, file_info):
    """Lookup the symmetric key for a file.
    
    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file
        
    Returns:
        bytes: The symmetric key
        
    Raises:
        Exception: If the symmetric key cannot be found, an error message is raised
    """
    try:
        # Connect to the server and send the request header
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            acl_nonce = file_info["acl-nonce"]
            
            request_header = f"""{{
                type: symmetric-key-lookup
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
        
        # Check if the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        # Decrypt the symmetric key
        try:
            symmetric_key = private_key.decrypt(
                base64.urlsafe_b64decode(header["encrypted-symmetric-key"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise Exception("Failed to decrypt symmetric key")
        
        return symmetric_key
    except Exception as e:
        raise Exception("Failed to lookup symmetric key")
    
def grant_access(public_key, private_key, email, access_token, server_address, server_port, file_info, user_email, user_permission):
    """Grant access to a user for a file.
    
    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file
        user_email (str): The email of the user to grant access to
        user_permission (str): The permissions to grant to the user
        
    Raises:
        Exception: If the user cannot be found, an error message is raised
    """
    try:
        # Lookup the user's public key
        user_public_key = user_lookup(public_key, private_key, email, access_token, server_address, server_port, user_email)
        if user_public_key == None:
            raise Exception("User not found")
        
        # Lookup the encrypted symmetric key for the file to grant access to
        symmetric_key = symmetric_key_lookup(public_key, private_key, email, access_token, server_address, server_port, file_info)
        if symmetric_key == None:
            raise Exception("Failed to find symmetric key")
        
        # Create a request header to grant access to the user and send it to the server
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode()
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            acl_nonce = file_info["acl-nonce"]
            
            request_header = f"""{{
                type: grant-access
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                file-name: {file_name}
                acl-name: {acl_name}
                acl-nonce: {acl_nonce}
                acl-symmetric-key: {acl_symmetric_key}
                shared-email: {user_email}
                permissions: {user_permission}
                encrypted-symmetric-key: {base64.urlsafe_b64encode(user_public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )).decode()}
            }}"""
            
            conn = open_connection(server_address, server_port)
            send_header(conn, private_key, request_header)
        except Exception as e:
            raise Exception("Failed to encrypt file info")
        
        # Check if the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])

        try:
            email_hash = header["email-hash"]
        except Exception as e:
            raise Exception("Failed to parse response")
        
        with open("assets/files.json", "r") as f:
            files = json.load(f)
        files[file_info["remote-file"]]["users"][email_hash] = user_email
        with open("assets/files.json", "w") as f:
            json.dump(files, f)
        
        # Generate notifications for the new user and the other affected users
        try:
            file_info = files[file_info["remote-file"]]
            
            notifications = {}
            access_list = get_access(public_key, private_key, email, access_token, server_address, server_port, file_info)
            for user in access_list.keys():
                if user == user_email:
                    continue
                if user == email:
                    continue
                
                user_public_key = user_lookup(public_key, private_key, email, access_token, server_address, server_port, user)
                
                content = {
                    "remote-file": file_info["remote-file"],
                    "email-hash": email_hash,
                    "email": user_email,
                }
                content = json.dumps(content)
                content = base64.urlsafe_b64encode(content.encode())
                symmetric_key, encrypted_symmetric_key = generate_symmetric_key(user_public_key)
                nonce = secrets.token_bytes(16)
                # Encrypt the content with the symmetric key
                cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_content = encryptor.update(content) + encryptor.finalize()
                encrypted_content = base64.urlsafe_b64encode(encrypted_content).decode()
                
                notifications[user] = {
                    "type": "new-access",
                    "encrypted-content": encrypted_content,
                    "nonce": base64.urlsafe_b64encode(nonce).decode(),
                    "encrypted-symmetric-key": base64.urlsafe_b64encode(encrypted_symmetric_key).decode(),
                }
                
            # Create a notification for the new user
            user_public_key = user_lookup(public_key, private_key, email, access_token, server_address, server_port, user_email)
            content = json.dumps(file_info)
            content = base64.urlsafe_b64encode(content.encode()).decode()
            symmetric_key, encrypted_symmetric_key = generate_symmetric_key(user_public_key)
            nonce = secrets.token_bytes(16)
            # Encrypt the content with the symmetric key
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CTR(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_content = encryptor.update(content.encode()) + encryptor.finalize()
            encrypted_content = base64.urlsafe_b64encode(encrypted_content).decode()
            
            notifications[user_email] = {
                "type": "grant-access",
                "encrypted-content": encrypted_content,
                "nonce": base64.urlsafe_b64encode(nonce).decode(),
                "encrypted-symmetric-key": base64.urlsafe_b64encode(encrypted_symmetric_key).decode(),
            }
        except Exception as e:
            raise Exception("Failed to generate notifications")
        
        # Send the notifications to the server
        try:
            request_header = f"""{{
                type: notifications
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                notifications: {base64.urlsafe_b64encode(json.dumps(notifications).encode()).decode()}
            }}"""
            send_header(conn, private_key, request_header)
        except Exception as e:
            raise Exception("Failed to send notifications")
        
        # Check if the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
    except Exception as e:
        print(f"Failed to grant access: {e}")
        input("Press enter to continue...")
        
def revoke_access(public_key, private_key, email, access_token, server_address, server_port, file_info, user_email):
    """Revoke access from a user for a file.
    
    Args:
        public_key (RSAPublicKey): The user's public key
        private_key (RSAPrivateKey): The user's private key
        email (str): The user's email address
        access_token (str): The user's access token
        server_address (str): The address of the server
        server_port (int): The port of the server
        file_info (dict): The information about the file
    """     
    try:
        # Generate a notification for the user
        try:
            notifcation = {
                "type": "revoke-access",
                "remote-file": file_info["remote-file"],
            }
            content = json.dumps(notifcation)
        except Exception as e:
            raise Exception("Failed to generate notification")
        
        # Connect to the server and send the request header
        try:
            public_key_base64 = base64.urlsafe_b64encode(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
            file_name = file_info["remote-file"]
            acl_name = file_info["remote-acl"]
            acl_symmetric_key = file_info["acl-symmetric-key"]
            acl_nonce = file_info["acl-nonce"]
        except Exception as e:
            print(e)
            raise Exception("Failed to generate header")
            
        try:
            request_header = f"""{{
                type: revoke-access
                public-key: {public_key_base64}
                email: {email}
                access-token: {access_token}
                file-name: {file_name}
                acl-name: {acl_name}
                acl-nonce: {acl_nonce}
                acl-symmetric-key: {acl_symmetric_key}
                shared-email: {user_email}
                notification: {base64.urlsafe_b64encode(content.encode()).decode()}
            }}"""
            conn = open_connection(server_address, server_port)
        except Exception as e:
            print(e)
            raise Exception("Failed to connect to server")
        
        try:
            send_header(conn, private_key, request_header)
        except Exception as e:
            print(e)
            raise Exception("Failed to send content")
        
        # Check if the response is successful
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
    except Exception as e:
        print(f"Failed to revoke access: {e}")
        input("Press enter to continue...")
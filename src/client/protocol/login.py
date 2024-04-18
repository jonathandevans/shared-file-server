from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from protocol.connect import parse_header, open_connection, send_header
import base64
import os
import socket
import ssl

def create_user_cert(email, public_key, cert_host, cert_port):
    """Request a certificate for the user from the certificate authority.
    
    Args:
        email (str): The user's email address
        public_key (RSAPublicKey): The user's public key
        cert_host (str): The address of the certificate authority
        cert_port (int): The port of the certificate authority
        
    Returns:
        str: The filename of the certificate
    """
    try:
        # Connect to the certificate authority
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _socket.bind(("", 0))
        _socket.connect((cert_host, cert_port))
        
        # Wrap the socket in an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("../ca-cert.pem")
        context.check_hostname = False
        _socket = context.wrap_socket(_socket, server_hostname=cert_host)
        
        header = f"""
        public-key: {base64.urlsafe_b64encode(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode()}
        common-name: {email}
        """
        header_length = len(header.encode())
        _socket.sendall(header_length.to_bytes(4, "big"))
        _socket.sendall(header.encode())
        
        cert_length = int.from_bytes(_socket.recv(4), "big")
        cert = _socket.recv(cert_length)
        
        with open(f"assets/cert.pem", "wb") as f:
            f.write(cert)
    except Exception as e:
        raise Exception("Failed to create certificate")

def register(email, password, server_address, server_port, cert_addr, cert_port):
    """Register a new user with the server. This function will generate a new key pair
    for the user and send the public key to the server. The server will then create a 
    certificate for the user.
    
    Args:
        email (str): The user's email address
        password (str): The user's password
        server_address (str): The address of the server
        server_port (int): The port of the server
        
    Returns:
        RSAPublicKey: The user's public key
        RSAPrivateKey: The user's private key
        str: The user's access token
        
    Raises:
        Exception: If the registration fails for any reason, an error message is raised
    """
    # Check if the assets directory exists
    if not os.path.exists("assets"):
        os.mkdir("assets")
    
    try:
         # Generate a new key pair
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Store the key in a file
        with open("assets/key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption((email + password).encode())
            ))
        private_key = key
        public_key = key.public_key()
    except Exception as e:
        raise Exception("Failed to create key pair")
    
    try:
        create_user_cert(email, public_key, cert_addr, cert_port)
    except Exception as e:
        if os.path.exists("assets/key.pem"):
            os.remove("assets/key.pem")
        raise Exception("Failed to create certificate")
    
    # Open a connection to the server
    try:
        conn = open_connection(server_address, server_port)
    except Exception as e:
        raise Exception("Failed to connect to server")
    
    # Send the request to the server
    try:    
        request = f"""{{
            type: register
            email: {email}
            public-key: {base64.urlsafe_b64encode(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode()}
            content-length: {os.path.getsize("assets/cert.pem")}
        }}"""
        send_header(conn, private_key, request)
        with open("assets/cert.pem", "rb") as f:
            conn.sendfile(f)
    except Exception as e:
        raise Exception("Failed to send register request")
    
    # Parse the header and return the keys 
    try:
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
        
        return public_key, private_key, header["access-token"]
    except Exception as e:
        raise Exception("Failed to parse header")

def login(email, password, server_address, server_port, cert_addr, cert_port):
    """
    Login to the server using the user's email and password. This function will load the
    user's private key and public key from the assets directory and send the public key to
    the server. The server will then verify the user's identity and return an access token.
    
    Args:
        email (str): The user's email address
        password (str): The user's password
        server_address (str): The address of the server
        server_port (int): The port of the server
        
    Returns:
        RSAPublicKey: The user's public key
        RSAPrivateKey: The user's private key
        str: The user's access token"""
    try:
        # Check if the assets directory exists
        if not os.path.exists("assets"):
            os.mkdir("assets")
        if not os.path.exists("assets/temp"):
            os.mkdir("assets/temp")
    except Exception as e:
        raise Exception("Failed to create assets directory")

    # Check if the key file exists
    if not os.path.exists("assets/key.pem"):
        return register(email, password, server_address, server_port, cert_addr, cert_port)
    else:
        try:
            conn = open_connection(server_address, server_port)
        except Exception as e:
            raise Exception("Failed to connect to server")
        
        try:
            with open("assets/key.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=(email + password).encode(),
                    backend=default_backend()
                )
                public_key = private_key.public_key()
        except Exception as e:
            raise Exception("Failed to load key pair")
        
        try:
            request = f"""{{
                type: login
                email: {email}
                public-key: {base64.urlsafe_b64encode(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).decode()}
                content-length: {os.path.getsize("assets/cert.pem")}
            }}"""
            send_header(conn, private_key, request)
            with open("assets/cert.pem", "rb") as f:
                conn.sendfile(f)
        except Exception as e:
            raise Exception("Failed to send login request")
            
        header = parse_header(conn)
        if header["status"] == "error":
            raise Exception(header["message"])
            
        return public_key, private_key, header["access-token"]
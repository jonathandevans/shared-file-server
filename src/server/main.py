from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from protocol.login import login, register
from protocol.header import parse_header, check_access_token
from protocol.files import upload, download, delete, replace
from protocol.notif import request_notifs
from protocol.share import get_access, grant_access, revoke_access, user_lookup, symmetric_key_lookup, check_access
import base64
import os
import socket
import ssl

server_address = None
server_port = None
ca_address = None
ca_port = None

public_key = None
private_key = None

def create_cert():
    """Create a certificate for the server from the certificate authority.
    
    Raises:
        Exception: If the certificate creation fails for any reason, an error message
            is raised
    """
    try:        
        # Connect to the certificate authority
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _socket.bind(("", 0))
        _socket.connect((ca_address, ca_port))
        
        # Wrap the socket in an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("../ca-cert.pem")
        context.check_hostname = False
        _socket = context.wrap_socket(_socket, server_hostname=ca_address)
        
        # Send the server's public key and common name to the certificate authority
        header = f"""
        public-key: {base64.urlsafe_b64encode(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode()}
        common-name: {server_address}
        """
        header_length = len(header.encode())
        _socket.sendall(header_length.to_bytes(4, "big"))
        _socket.sendall(header.encode())
        
        # Receive the certificate from the certificate authority
        cert_length = int.from_bytes(_socket.recv(4), "big")
        cert = _socket.recv(cert_length)
        with open("assets/cert.pem", "wb") as f:
            f.write(cert)
    except Exception as e:
        raise Exception("Failed to create certificate")

def check_identity():
    """Check if the server has a public and private key. If not, generate a new key pair
    and store them in the assets directory.
    Using the public key, ask the certificate authority for a certificate and store it in
    the assets directory.
    """
    global public_key, private_key
    
    # Check if the assets directory exists
    if not os.path.exists("assets"):
        os.mkdir("assets")
        
    # Check if the key file exists
    if not os.path.exists("assets/key.pem"):
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
                encryption_algorithm=serialization.NoEncryption()
            ))
        private_key = key
        public_key = key.public_key()
    else:
        with open("assets/key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            public_key = private_key.public_key()
            
    # Check if the certificate file exists
    if not os.path.exists("assets/cert.pem"):
        create_cert()

def handle_client(client_socket):
    """Handle a client connection by parsing the header and calling the appropriate function.

    Args:
        client_socket (socket): The client socket to handle
    """
    try:
        header = parse_header(client_socket)
        
        # print(f"Received header from {client_socket.getpeername()}: {header}")
        
        if header["type"] == "register":
            register(client_socket, header, private_key)
        elif header["type"] == "login":
            login(client_socket, header, private_key)
            
        elif header["type"] == "upload":
            if check_access_token(client_socket, header, public_key):
                upload(client_socket, header)
        elif header["type"] == "download":
            if check_access_token(client_socket, header, public_key):
                download(client_socket, header)
        elif header["type"] == "delete":
            if check_access_token(client_socket, header, public_key):
                delete(client_socket, header)
        elif header["type"] == "replace":
            if check_access_token(client_socket, header, public_key):
                replace(client_socket, header)
                
        elif header["type"] == "grant-access":
            if check_access_token(client_socket, header, public_key):
                grant_access(client_socket, header)
        elif header["type"] == "revoke-access":
            if check_access_token(client_socket, header, public_key):
                revoke_access(client_socket, header)
                
        elif header["type"] == "get-notifications":
            if check_access_token(client_socket, header, public_key):
                request_notifs(client_socket, header)
        
        elif header["type"] == "get-access":
            if check_access_token(client_socket, header, public_key):
                get_access(client_socket, header)
        elif header["type"] == "user-lookup":
            if check_access_token(client_socket, header, public_key):
                user_lookup(client_socket, header)
        elif header["type"] == "symmetric-key-lookup":
            if check_access_token(client_socket, header, public_key):
                symmetric_key_lookup(client_socket, header)
        elif header["type"] == "check-access":
            if check_access_token(client_socket, header, public_key):
                check_access(client_socket, header)
        else:
            raise Exception("Invalid header")
    except Exception as e:
        print(f"Error handling client {client_socket.getpeername()}: {e}")

def run_server():
    """Run the server application. This function creates a TCP socket and listens for incoming
    connections. When a connection is accepted, the client handling function is submitted to a
    thread pool for execution.
    """
    # Check if the certificate and key files exist
    try:
        with open("assets/cert.pem") as f:
            pass
        with open("assets/key.pem") as f:
            pass
    except FileNotFoundError:
        print("Could not find cert.pem or key.pem")
        return
    
    # Create a TCP socket and bind it to the specified port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", server_port))
    server_socket.listen(5)
    
    # Wrap the socket in a TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("assets/cert.pem", "assets/key.pem")
    # Create a ThreadPoolExecutor with a maximum of 10 threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        print(f"Server running on port {server_port} with a thread pool of 10")

        # Accept and handle client connections
        while True:
            try:
                # Block and wait for an incoming connection
                client_socket, addr = server_socket.accept()
                ssl_socket = context.wrap_socket(client_socket, server_side=True)

                # Submit the client handling function to the thread pool
                executor.submit(handle_client, ssl_socket)
            except Exception as e:
                print(f"Error accepting connection: {e}")

def main():
    parser = ArgumentParser(description="Run the secure file share server application.")
    parser.add_argument("-a", "--addr", type=str, default="localhost", help="The host address to listen on.")
    parser.add_argument("-p", "--port", type=int, default=8080, help="The port to listen on.")
    parser.add_argument("-A", "--cert-auth-addr", type=str, default="localhost", help="The host address of the certificate authority.")
    parser.add_argument("-P", "--cert-auth-port", type=int, default=8084, help="The port of the certificate authority.")
    args = parser.parse_args()
    if args.port < 1024 or args.port > 65535:
        print("Port must be between 1024 and 65535")
        return
    if args.cert_auth_port < 1024 or args.cert_auth_port > 65535:
        print("Certificate authority port must be between 1024 and 65535")
        return
    
    # Assign the global variables
    global server_address, server_port, ca_address, ca_port
    server_address = args.addr
    server_port = args.port
    ca_address = args.cert_auth_addr
    ca_port = args.cert_auth_port
    
    check_identity()
    run_server()

if __name__ == "__main__":
    main()
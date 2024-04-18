from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import secrets
import socket
import ssl

def open_connection(host, port):
    """Open a connection to the server and wrap it in an SSL context.

    Args:
        host (str): The server's address
        port (int): The server's port

    Raises:
        e: If the connection fails for any reason, an error message is raised

    Returns:
        ssl.SSLSocket: The SSL wrapped
    """
    try:
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _socket.bind(("", 0))
        _socket.connect((host, port))
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("../ca-cert.pem")
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context.wrap_socket(_socket, server_hostname=host)
    except Exception as e:
        raise e
    
def parse_header(client_socket):
    """Parse the header from the client and return the header dictionary.

    Args:
        client_socket (socket): The client's socket

    Raises:
        Exception: If the header is invalid, an error is raised

    Returns:
        dict: The key-value pairs from the header
    """
    try:
        header_size = int.from_bytes(client_socket.recv(4), "big")
        header_bytes = client_socket.recv(header_size)
        
        header = header_bytes.decode()
        header_dict = {}
        
        for line in header.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                header_dict[key.strip()] = value.strip()
    except Exception as e:
        raise Exception("Failed to parse header")
    
    return header_dict

def send_header(conn, private_key, content):
    """Used to send a signed header to the server.

    Args:
        conn (socket): The connection to the server
        private_key (RSAPrivateKey): The private key used to sign the content
        content (str): The content to send to the server
    """
    hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash.update(content.encode())
    hash = hash.finalize()
    signature = private_key.sign(
        hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    conn.sendall(len(content.encode()).to_bytes(4, "big"))
    conn.sendall(len(signature).to_bytes(4, "big"))
    conn.sendall(signature)
    conn.sendall(content.encode())
    
def generate_symmetric_key(public_key):
    """Generates a symmetric key and encrypts it with the provided public key.

    Args:
        public_key (RSAPublicKey): The public key to encrypt the symmetric key with

    Returns:
        tuple: A tuple containing the symmetric key and the encrypted symmetric key
    """
    symmetric_key = secrets.randbits(256).to_bytes(32, 'big')
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return symmetric_key, encrypted_symmetric_key
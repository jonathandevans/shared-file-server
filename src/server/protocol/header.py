from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import datetime

def check_access_token(client_socket, header, server_public_key):
    """
    Check the access token provided by the client. The access token should be in the header
    and should be a base64 encoded string containing the following information:
    - public-key: The public key of the client
    - email: The email of the client
    - expiration: The expiration date of the access token
    - nonce: A unique nonce
    - signature: The signature of the access token
    
    The access token is verified by checking the following:
    - The public key in the access token matches the public key in the header
    - The email in the access token matches the email in the header
    - The expiration date has not passed
    - The signature is valid
    
    If the access token is invalid, an error message is sent to the client and the function returns False.
    
    Args:
        client_socket (socket): The client's socket
        header (dict): The header dictionary
        server_public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): The server's public key"""
    try:
        access_token = header["access-token"]
        token_bytes = base64.urlsafe_b64decode(access_token.encode())
        token = token_bytes.decode()
        
        if "public-key" not in token or "expiration" not in token or "nonce" not in token or "signature" not in token or "email" not in token:
            raise Exception("Invalid access token")
        
        public_key = None
        expiration = None
        email = None
        for line in token.split("\n"):
            if "public-key" in line:
                public_key = line.split(":")[1].strip()
            if "expiration" in line:
                expiration = line.split(":")[1].strip()
            if "email" in line:
                email = line.split(":")[1].strip()
        
        # Check the public key in the access token matches the public key in the header
        if public_key != header["public-key"]:
            raise Exception("Public key in token does not match public key in header")
        # Check the email in the access token matches the email in the header
        if email != header["email"]:
            raise Exception("Email in token does not match email in header")
        
        # Check the expiration date
        expiration = datetime.datetime.fromisoformat(expiration)
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=datetime.timezone.utc)
        if expiration < datetime.datetime.now(datetime.timezone.utc):
            raise Exception("Access token has expired")
        
        # Verify the signature
        access_token_no_sig = "\n".join(token.split("\n")[:-1])
        hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash.update(access_token_no_sig.encode())
        hash = hash.finalize()
        signature = base64.urlsafe_b64decode(token.split("\n")[-1].split(":")[1].strip().encode())
        server_public_key.verify(
            signature,
            hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
    except Exception as e:
        response = f"""{{
            status: error
            message: Invalid access token  
        }}"""
        client_socket.sendall(len(response).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        return False
        
def parse_header(client_socket):
    """Parse the header from the client and verify the signature using the public key
    provided in the header.

    Args:
        client_socket (socket): The client's socket

    Raises:
        Exception: If the header is invalid or the signature is invalid, an error is raised

    Returns:
        dict: The header dictionary
    """
    try:
        header_size = int.from_bytes(client_socket.recv(4), "big")
        signature_size = int.from_bytes(client_socket.recv(4), "big")
        
        signature = client_socket.recv(signature_size)
        header_bytes = client_socket.recv(header_size)
        
        header = header_bytes.decode()
        header_dict = {}
        
        for line in header.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                header_dict[key.strip()] = value.strip()
                
        public_key = serialization.load_pem_public_key(
            base64.urlsafe_b64decode(header_dict["public-key"]),
            backend=default_backend()
        )

        hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash.update(header.encode())
        header_hash = hash.finalize()
        public_key.verify(
            signature,
            header_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise Exception("Failed to parse header")
    
    return header_dict
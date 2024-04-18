from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import os
import datetime

def generate_access_token(public_key, private_key, email):
    """Create an access token for the user based on their public key. This token 
    is signed by the server's private key and can be used to authenticate the user.
    
    Args:
        public_key (str): The user's public key in base64 format
        private_key (RSAPrivateKey): The server's private key
        email (str): The user's email address
        
    Returns:
        str: The access token in base64 format
    """
    token = f"""public-key: {public_key}
    email: {email}
    expiration: {datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)}
    nonce: {os.urandom(16).hex()}"""
    
    # Hash the token
    hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash.update(token.encode())
    hash = hash.finalize()
    # Sign the hash
    signature = private_key.sign(
        hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    token += f"\nsignature: {base64.urlsafe_b64encode(signature).decode()}"

    # Encode the token to base64
    token = base64.urlsafe_b64encode(token.encode()).decode()
    return token

def verify_certificate(cert_file, public_key, email):
    """Verify the user's certificate using the CA's certificate.
    
    Args:
        cert_file (str): The path to the user's certificate
        public_key (RSAPublicKey): The user's public key
        email (str): The user's email address
        
    Raises:
        Exception: If the certificate is invalid, an error is raised
    """
    try:
        # Load the certificate
        with open(cert_file, "rb") as f:
            cert = f.read()
        
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
        
        # Check if the public key in the certificate matches the public key in the header
        if public_key is not None:
            cert_public_key = cert.public_key()
            if cert_public_key != public_key:
                raise Exception("Public key does not match certificate")
        # Check if the common name in the certificate matches the email
        if email != cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value:
            raise Exception("Common name does not match email")
    except Exception as e:
        raise Exception("Failed to verify user certificate")

def login(client_socket, header, private_key):
    """Handle the login request from the client. This function verifies the user's
    certificate and generates an access token for the user.
    
    Args:
        client_socket (socket.socket): The client's socket
        header (dict): The header dictionary from the client
        private_key (RSAPrivateKey): The server's private key
        
    Raises:
        Exception: If the login fails for any reason, an error message is sent to the client
    """
    try:
        try:
            public_key = serialization.load_pem_public_key(
                base64.urlsafe_b64decode(header["public-key"].encode()),
                backend=default_backend()
            )
            email = header["email"]
        except Exception as e:
            raise Exception("Login failed")
        
        # Try to find the hashed email in the users.csv file
        cert_file = None
        with open("assets/users.csv", "r") as f:
            for line in f:
                if email == line.split(",")[0]:
                    cert_file = line.split(",")[2].strip()
                    break
            else:
                raise Exception("Email not found")
        
        # Verify the local certificate, if it fails, try to verify the certificate sent by the client
        # and if successful, store the certificate
        try:
            verify_certificate(f"assets/store/{cert_file}", public_key, email)
        except Exception as e:
            try:
                if not os.path.exists(f"assets/temp"):
                    os.mkdir("assets/temp")
                with open(f"assets/temp/{cert_file}", "wb") as f:
                    f.write(client_socket.recv(header["content-length"]))
                verify_certificate(f"assets/temp/{cert_file}", public_key, email)
                os.rename(f"assets/temp/{cert_file}", f"assets/store/{cert_file}")
            except Exception as e:
                raise Exception("Failed to verify user certificate")
            finally:
                if os.path.exists(f"assets/temp/{cert_file}"):
                    os.remove(f"assets/temp/{cert_file}")
        
        # Generate an access token
        try:
            access_token = generate_access_token(header["public-key"], private_key, email)
        except Exception as e:
            raise Exception("Failed to generate access token")
        
        response = f"""{{
            status: success
            access-token: {access_token}
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
    except Exception as e:
        response = f"""{{
            status: error
            message: "{e}"
        }}
        """
        client_socket.sendall(len(response.encode()).to_bytes(4, "big"))
        client_socket.sendall(response.encode())
        raise e
    
def register(client_socket, header, private_key):
    """Handle the register request from the client. This function generates a certificate
    for the user and sends it back to the client.
    
    Args:
        client_socket (socket.socket): The client's socket
        header (dict): The header dictionary from the client
        ca_address (str): The address of the certificate authority
        ca_port (int): The port of the certificate authority
        private_key (RSAPrivateKey): The server's private key
        
    Raises:
        Exception: If the registration fails for any reason, an error message is sent to the client
    """
    try:
        if not os.path.exists("assets"):
            os.mkdir("assets")
        
        # Parse the public key and email from the header
        try:
            public_key = serialization.load_pem_public_key(
                base64.urlsafe_b64decode(header["public-key"].encode()),
                backend=default_backend()
            )
            email = header["email"]
        except Exception as e:
            raise Exception("Failed to parse header")
        
        # Check if the email is already registered
        try:
            with open("assets/users.csv", "r") as f:
                for line in f:
                    if email == line.split(",")[0]:
                        raise Exception("Email already registered")
        except FileNotFoundError:
            pass
        except Exception as e:
            raise Exception("Email already registered")
        
        # Download the certificate from the client
        try:
            if not os.path.exists("assets/store"):
                os.mkdir("assets/store")
            
            filename = os.urandom(16).hex()
            while os.path.exists(f"assets/store/{filename}.pem"):
                filename = os.urandom(16).hex()
            with open(f"assets/store/{filename}", "wb") as f:
                f.write(client_socket.recv(int(header["content-length"])))
        except Exception as e:
            raise Exception("Failed to store certificate")
        
        # Verify the certificate
        try:
            verify_certificate(f"assets/store/{filename}", public_key, email)
        except Exception as e:
            os.remove(f"assets/store/{filename}")
            raise Exception("Failed to verify user certificate")
        
        # Generate an access token
        try:
            access_token = generate_access_token(header["public-key"], private_key, email)
        except Exception as e:
            raise Exception("Failed to generate registeraccess token")
        
        # Store the user information
        try:
            # Create a user.csv file if it doesn't exist
            if not os.path.exists("assets/users.csv"):
                with open("assets/users.csv", "w") as f:
                    f.write("email,public-key,certificate\n")
                    f.write(f"{email},{header['public-key']},{filename}\n")
            else:
                with open("assets/users.csv", "a") as f:
                    f.write(f"{email}, {header['public-key']}, {filename}\n")
        except Exception as e:
            raise Exception("Failed to store user information")
        
        response = f"""{{
            status: success
            access-token: {access_token}
        }}
        """
        response_length = len(response.encode())
        client_socket.sendall(response_length.to_bytes(4, "big"))
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
    
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
import base64
import datetime
import socket
import ssl

private_key = None

def handle_client(client_socket):
    try:
        header_length = int.from_bytes(client_socket.recv(4), "big")
        header = client_socket.recv(header_length).decode()
        for line in header.split("\n"):
            if "common-name" in line:
                common_name = line.split(": ")[1].strip()
            elif "public-key" in line:
                public_key = serialization.load_pem_public_key(base64.urlsafe_b64decode(line.split(": ")[1].strip()), backend=default_backend())
            
        # Create a certificate using the certificate authority's pem and private key
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
        ).issuer_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Certificate Authority")])
        ).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        cert_bytes = cert.public_bytes(Encoding.PEM)
        
        with open("../ca-cert.pem", "rb") as f:
            ca_cert_bytes = f.read()
        cert_bytes += ca_cert_bytes
        
        cert_length = len(cert_bytes)
        client_socket.sendall(cert_length.to_bytes(4, "big"))
        client_socket.sendall(cert_bytes)
    except Exception as e:
        print(f"Error handling client {client_socket.getpeername()}: {e}")
        client_socket.close()

def run_server(port):
    # Check if the certificate and key files exist
    try:
        with open("../ca-key.pem") as f:
            pass
        with open("../ca-cert.pem") as f:
            pass
    except FileNotFoundError:
        print("Could not find ca-cert.pem or ca-key.pem")
        return
    
    # Load the certificate authority's private key and certificate
    global private_key
    with open("../ca-key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Create a TCP socket and bind it to the specified port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", port))
    server_socket.listen(5)
    
    # Wrap the socket in a TLS context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("../ca-cert.pem", "../ca-key.pem")

    # Create a ThreadPoolExecutor with a maximum of 10 threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        print(f"Server running on port {port} with a thread pool of 10")

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
    parser.add_argument("-p", "--port", type=int, default=8084, help="The port to run the certificate authority server on.")
    args = parser.parse_args()
    if args.port < 1024 or args.port > 65535:
        print("Port must be between 1024 and 65535")
        return
    
    run_server(args.port)

if __name__ == '__main__':
    main()
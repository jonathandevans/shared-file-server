from argparse import ArgumentParser
from protocol.login import login
from protocol.files import upload, download, replace, delete
from protocol.notif import request_notifs
from protocol.share import grant_access, revoke_access, get_access
import os
import json

server_address = None
server_port = None

email = None
private_key = None
public_key = None
access_token = None

def print_user():
    """Print the user's email to the console
    """
    print("\033[H\033[J" + f"Logged In As: {email}")
    print("-----")

def print_share_options(file):
    """Print the share options for a file to the console and allow the user to interact with them.
    """
    while True:
        print_user()
        
        with open("assets/files.json", "r") as f:
            files = json.load(f)
        file = files[file["remote-file"]]
        
        permissions = get_access(public_key, private_key, email, access_token, server_address, server_port, file)
        print(f"Access list for {file['filename']}:")
        for user in permissions:
            string = f"  {user}"
            if permissions[user] == 0:
                string += " (Owner)"
            elif permissions[user] == 1:
                string += " (Editor)"
            elif permissions[user] == 2:
                string += " (Viewer)"
            print(string)
        
        print()
        if permissions[email] == 0 or permissions[email] == 1:
            print("- Add <email>")
            print("- Remove <email>")
        print("- Back")
        command = input("Enter a command: ")
        
        if command.lower() == "back":
            return
        elif command.lower().startswith("add"):
            permission = input("Enter the permission level (1=editor, 2=viewer): ")
            
            try:
                permission = int(permission)
                if permission < 1 or permission > 2:
                    raise Exception("Invalid permission level")
            except:
                print("Invalid permission level")
                continue
            
            grant_access(public_key, private_key, email, access_token, server_address, server_port, file, command.split()[1], permission)
        elif command.lower().startswith("remove"):
            revoke_access(public_key, private_key, email, access_token, server_address, server_port, file, command.split()[1])

def run_client():
    """Run the client application. This function displays the user interface and processes user commands.
    """
    if not os.path.exists("assets/files.json"):
        with open("assets/files.json", "w") as f:
            f.write("{}")
    
    while True:
        request_notifs(public_key, private_key, email, access_token, server_address, server_port)
        
        print_user()
        
        with open("assets/files.json", "r") as f:
            files = json.load(f)
        files_list = list(files.keys())
        
        if not files_list:
            print("No files")
        else:
            print("Filename - Filesize - Updated - Owner")
            for i, key in enumerate(files_list):
                file = files[key]
                print(f"{i + 1}. {file['filename']} - {file['filesize']} bytes - {file['updated']} - {file['owner']}")
        
        print()
        print("- Upload <filepath>")
        if files_list:
            print("- Download <file number>")
            print("- Delete <file number>")
            print("- Share <file number>")
            print("- Replace <file number>")
        print("- Refresh")
        print("- Logout")
        choice = input("Enter a command: ")
        
        if choice.lower() == "logout":
            return
        elif choice.lower() == "refresh":
            continue
        elif choice.lower().startswith("upload"):
            upload(public_key, private_key, email, access_token, server_address, server_port, choice.split()[1])
        elif choice.lower().startswith("download"):
            try:
                download(public_key, private_key, email, access_token, server_address, server_port, files[files_list[int(choice.split()[1]) - 1]])
            except:
                continue
        elif choice.lower().startswith("delete"):
            try:
                delete(public_key, private_key, email, access_token, server_address, server_port, files[files_list[int(choice.split()[1]) - 1]])
            except:
                continue
        elif choice.lower().startswith("share"):
            try:
                print_share_options(files[files_list[int(choice.split()[1]) - 1]])
            except:
                continue
        elif choice.lower().startswith("replace"):
            try:
                filepath = input("Enter the new file path: ")
                replace(public_key, private_key, email, access_token, server_address, server_port, files[files_list[int(choice.split()[1]) - 1]], filepath)
            except:
                continue

def main():
    # Parse command line arguments
    parser = ArgumentParser(description="Run the secure file share client application.")
    parser.add_argument("-a", "--addr", type=str, default="localhost", help="The host address of the server to connect to.")
    parser.add_argument("-p", "--port", type=int, default=8080, help="The port to connect to on the server.")
    parser.add_argument("-A", "--cert-addr", type=str, default="localhost", help="The host address of the certificate authority server.")
    parser.add_argument("-P", "--cert-port", type=int, default=8084, help="The port to connect to on the certificate authority server.")
    args = parser.parse_args()
    if args.port < 1024 or args.port > 65535:
        print("Port must be between 1024 and 65535")
        return
    global server_address, server_port
    server_address = args.addr
    server_port = args.port
    
    # Get the user's email and password
    global email
    email = input("\033[H\033[J" + "Enter your email: ")
    password = input("Enter your password: ")
    
    # Login to the server
    global public_key, private_key, access_token
    try:
        public_key, private_key, access_token = login(email, password, server_address, server_port, args.cert_addr, args.cert_port)
    except Exception as e:
        print(f"Failed to login: {e}")
        return
    
    # Run the client application
    run_client()
    
if __name__ == "__main__":
    main()

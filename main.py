from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
import os


slat_file = 'salt.db'
salt = None
key = None
encrypted_file_extension = 'yash_encrypt'
auth_test_file = 'auth_test_file.bin'

def encrypt_data(data):
    global key
    if not key:
        raise ValueError("Encryption key is not set.")
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_data(encrypted_data):
    global key
    if not key:
        raise ValueError("Decryption key is not set.")
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

def format_path(path):
    """
    Formats a file path to handle common issues:
    - Removes surrounding quotes
    - Normalizes path separators
    - Preserves legitimate spaces in file/folder names
    
    Args:
        path (str): The input path
        
    Returns:
        str: Formatted path
    """
    # Remove surrounding quotes if present, but preserve internal spaces
    if (path.startswith('"') and path.endswith('"')) or (path.startswith("'") and path.endswith("'")):
        path = path[1:-1]
    
    # Normalize path separators for the current OS
    path = os.path.normpath(path)
    
    return path

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    return True


def generate_key(password):
    global salt, key
    if not salt:
        raise ValueError("Salt is not set.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))

def new_file_path(file_path):
    """
    Returns an available file path by adding a counter if the file already exists.
    
    Args:
        file_path (str): The original file path
        
    Returns:
        str: An available file path
    """
    if not os.path.exists(file_path):
        return file_path
    
    # Split the path into directory, name, and extension
    directory = os.path.dirname(file_path)
    basename = os.path.basename(file_path)
    name, ext = os.path.splitext(basename)
    
    counter = 1
    while True:
        # Create new filename with counter
        new_name = f"({counter}){name}{ext}"
        new_path = os.path.join(directory, new_name)
        
        if not os.path.exists(new_path):
            return new_path
        
        counter += 1

def encrypt_file(file_path):
    global key
    if not key:
        raise ValueError("Encryption key is not set.")
    folder_path = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    file_contents = None
    with open(file_path, 'rb') as f:
        file_contents = f.read()

    encrypted_file_path = new_file_path(os.path.join(folder_path, f"{file_name}.{encrypted_file_extension}"))
    encrypted_contents = encrypt_data(file_contents)
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_contents)
        
    print(f"File {file_name} encrypted successfully.")
    print(f"Encrypted file saved at: {encrypted_file_path}")

def decrypt_file(file_path):
    global key
    if not key:
        raise ValueError("Decryption key is not set.")
    folder_path = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    if not file_name.endswith(f".{encrypted_file_extension}"):
        print(f"File {file_name} is not encrypted using  this program.")
        return
    file_name = file_name[:-(len(encrypted_file_extension) + 1)]
    file_contents = None
    with open(file_path, 'rb') as f:
        file_contents = f.read()

    decrypted_contents = decrypt_data(file_contents)
    decrypted_file_path = new_file_path(os.path.join(folder_path, file_name))
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_contents)

    print(f"File {file_name} decrypted successfully.")
    print(f"Decrypted file saved at: {decrypted_file_path}")


def first_setup():
    global salt, key
    salt = os.urandom(16)
    password = input("Set Up a master password: ")
    while not validate_password(password):
        print("Password must be at least 8 characters long, contain uppercase and lowercase letters, and at least one digit.")
        password = input("Enter a master password: ")
    generate_key(password)
    with open(slat_file, 'wb') as f:
        f.write(salt)
    with open(auth_test_file, 'wb') as f:
        f.write(encrypt_data(b'test'))
    
    print("Setup complete. Your master password is set.")
    
def authenticate(count=1):
    global salt, key
    if not os.path.exists(slat_file):
        first_setup()
        return
    with open(slat_file, 'rb') as f:
        salt = f.read()
    password = input("Enter your master password: ")
    try:
        generate_key(password)
        with open(auth_test_file, 'rb') as f:
            fernet = Fernet(key)
            fernet.decrypt(f.read())
        print("Authentication successful.")
    except Exception as e:
        print(f"Authentication failed: {e}")
        if count < 3:
            print("Please try again.")
            authenticate(count + 1)
        else:
            print("Too many failed attempts. Exiting.")
            exit()


def main():
    if not os.path.exists(slat_file) or not os.path.exists(auth_test_file):
        first_setup()
    else:
        authenticate()

    while True:
        print("\n1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            file_path = format_path(input("Enter the path of the file to encrypt: "))
            if not os.path.exists(file_path):
                print("File does not exist.")
                continue
            encrypt_file(file_path)
            print("File encrypted successfully.")
            print("Do you want to remove original file?")
            print("1. Yes")
            print("2. No")
            choice = input("Enter your choice: ")
            if choice == '1':
                os.remove(file_path)
                print("Original file removed.")
            
        elif choice == '2':
            file_path = format_path(input("Enter the path of the file to decrypt: "))
            if not os.path.exists(file_path):
                print("File does not exist.")
                continue
            decrypt_file(file_path)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

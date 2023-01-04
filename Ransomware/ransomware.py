import pathlib, os, secrets, base64, getpass
import cryptography 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt






def generate_salt(size=16):
    """Generate the salt  used for key derivation. `size` ia the
    length of the salt to generate"""
    return secrets.token_bytes(size)
    #Secret is more stronger than to use random



def derive_key(salt, password):
    """
    Derive the key from the `password` using the passed `salt`
    """
    kdf = Scrypt.derived(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())




def load_salt():
    return open('salt.salt', 'rb').read()



def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    '''
    Generates a key from a `password` and the salt. 
    If `load_existing_salt` is True, it'll load the salt from a file
    in the current directory called "salt.salt".
    If `save_salt` is True, then it will generate a new salt and save it to "salt.salt
    '''
    if load_existing_salt:
        #load existing salt
        salt = load_salt()
    elif save_salt:
        #generate new salt and save it
        salt = generate_salt(salt_size)
        with open("salt.salt", "wb") as salt_file:
            salt_file.write(salt)

    #generate the key from the salt and the password
    derive_key = derive_key(salt, password)
    return base64.urlsafe_b64decode(derive_key)



#File Encryption
def encrypt(filename, key):
    '''
    Given a filename (str) and a key (bytes) it will encrypt and write it
    '''
    f = Fernet(key)
    with open(filename, 'rb') as file:
        #read all file data
        file_data = file.read()

    #encrypt data
    encrypted_data = f.encrypt(file_data)

    #write the encrypted file
    with open(filename, 'wb') as file:
        file.write(encrypted_data)


#Folder Encryption
def encrypt_folder(foldername, key):
    #if it's a folder, encrypt the entire folder even if it contains files
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            encrypt(child, key)
        elif child.is_dir():
            encrypt_folder(child, key)
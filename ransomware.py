import pathlib, os, secrets, base64, getpass
import cryptography 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt






def generate_salt(size=16):
    """Generate the salt  used for key derivation. `size` ia the
    length of the salt to generate"""
    return secrets.token_bytes(size)
    #Secret is more stronger than to use random





import sys
import os
import rsa
import hashlib
import logging
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from socket import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from Crypto.Hash import SHA256



# Configure the logging
log_file = 'tracker.log'
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


def log_activity(activity):
    # Log the activity with the current timestamp
    logging.info(f'{datetime.now()} - {activity}')

# # Example usage
# log_activity('Started the application')
# log_activity('Performed some activity')
# log_activity('Finished processing data')


def login(c, cnx):



    username = input("Enter username: ")
    password = input("Enter password: ")

    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        #key generated from rsa 
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize the public and private keys to PEM format
    public_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Load the public key from the PEM-encoded string
    rsa_public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    c.execute("SELECT password FROM users WHERE username=%s", (username,))
    result = c.fetchone()

    if result is None:
        print("Invalid Credentials !")
        log_activity("Username : %s tried to login in using wrong password" , username)

    else:
        # also need to log this activity
        stored_password_hash = result[0]

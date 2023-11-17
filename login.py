
import sys
import os
import threading
import pickle
from socket import *
import mysql.connector
import datetime
import time
from threading import Lock
import fcntl
import shutil
import rsa
import hashlib
import getpass
import getpass_asterisk
import base64
from Crypto.Util import asn1
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5



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
        if password_hash == stored_password_hash:
            log_activity("User %s has logged in and has access to DFS now !")
            print("Login successfull ! connecting to the server..")
            c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
            result = c.fetchone()[0]
            result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
            result = result.replace('\n-----END RSA PUBLIC KEY-----\n', '')
            public_key_str = result
            public_key_bytes = base64.b64decode(public_key_str)
            public_key = RSA.import_key(public_key_bytes)
            c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)",(username, username))
            result = c.fetchone()[0]
            # result = result.replace('-----BEGIN PRIVATE KEY-----\n', '')
            # result = result.replace('\n-----END PRIVATE KEY-----\n', '')
            privateKeyString = result
            private_key = RSA.import_key(privateKeyString)
            start_time = time.time()
            while True:
                command = int(input(
                    "Enter a command (\n 1. Create, \n 2. Read, \n 3. Write, \n 4. Restore,\n 5. Delete\n 6. exit \n): "))
                if command == 1:
                    message = username + ':create'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input("Enter a file name: ")
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    log_activity("user %s is trying to create file which is %s ", username, filename_encrypted)
                    print(data)
                    flag=1
                    file_id = int(client.recv(1024).decode('utf-8'))
                    while(flag):
                        set_permissions = input("Do you want to set permissions for other users? (y/n) ")
                        if set_permissions.lower() == 'y':
                            other_username = input("Enter the username of the user you want to give permissions to: ")
                            # c.execute("select public_key from acess_control where username=%s",(other_username,))
                            # other_user_pub_key = c.fetchone()
                            # other_user_pri_key =
                            c.execute("SELECT * FROM users WHERE username=%s", (other_username,))
                            if c.fetchone() is not None:
                                print(filename)
                                print(file_id)
                                # c.execute("SELECT file_id FROM files WHERE filename=%s", ('kp',))
                                # row = c.fetchone()
                                # file_id = row[0]
                                # print(row)
                                print("Enter the permissions you want to grant (read, write, delete, create, restore): ")
                                re = int(input())
                                wr = int(input())
                                delet = int(input())
                                cre = int(input())
                                rest = int(input())
                                c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (other_username,other_username))
                                other_user_pub_key = c.fetchone()[0]
                                # print(other_user_pub_key);
                                c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (other_username,other_username))
                                other_user_pri_key = c.fetchone()[0]
                                # print(other_user_pri_key);
                                c.execute("INSERT INTO acess_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(other_user_pub_key,other_user_pri_key,other_username,re, wr, delet, cre, rest, file_id));
                                # c.execute("UPDATE acess_control SET re = %s,wr = %s,delet = %s,cre = %s,rest = %s,file_id = %s where username=%s", (re, wr, delet, cre, rest, file_id,other_username))
                                cnx.commit()
                                print("do you want to give access to more users? y/n")
                                set_permissions = input()
                                if (set_permissions.lower() == 'y'):
                                    flag = 1
                                else:
                                    flag = 0
                        else:
                            print("Okay!!")
                elif command == 2:
                    message = username + ':read'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data_encrypted = client.recv(65536)
                    print("The encrypted data using RSA algorithm: ",data_encrypted)
                    log_activity("The new file was encrypted using RSA algoirthm ")
                    cipher = PKCS1_OAEP.new(private_key)
                    data = cipher.decrypt(data_encrypted).decode('utf-8')
                    print("The Decrypted data using User's private key of RSA:", data)
                    log_activity("The file decrypted using %s private key of RSA ", username)
                    read_message = client.recv(1024)
                    print(read_message)
                elif command == 3:
                    message = username + ':write'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    write_acess = client.recv(1024).decode('utf-8')
                    print(write_acess)
                    if(write_acess=='1'):
                        data_encrypted = client.recv(1024)
                        print("The encrypted data using RSA algorithm: ", data_encrypted)
                        log_activity("The new file was encrypted using RSA algoirthm ")
                        cipher = PKCS1_OAEP.new(private_key)
                        data = cipher.decrypt(data_encrypted).decode('utf-8')
                        print("The Current content and Decrypted data using User's private key of RSA:", data)
                        log_activity("The file decrypted using %s private key of RSA ", username)
                        new_data = input("Enter new content that you want to add: ")
                        client.send(new_data.encode('utf-8'))
                        write_message = client.recv(1024)
                        print(write_message)
                    else:
                        write_message = client.recv(1024)
                        print(write_message)
                elif command == 4:
                    message = username + ':restore'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                elif command == 5:
                    message = username + ':delete'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                else:
                    end_time = time.time()
                    execution_time = end_time - start_time
                    print("Total execution time: {:.2f} seconds".format(execution_time))
                    log_activity("Total Exection time for this activity : {:.2f} seconds".format(execution_time)) 
                    exit(0)
        else:
            print("Username or password is incorrect")
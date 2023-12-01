import sys
import os
import pickle
import threading
from socket import *
import pymysql
import mysql.connector
from mysql.connector import errorcode
import datetime
from threading import Lock
import fcntl
import shutil
import rsa
import time
import hashlib
import pkcs1
import sha256
import getpass
import getpass_asterisk
import base64
#from Crypto.util import asn1
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import logging

# Configure logging
logging.basicConfig(filename='/Users/saitejachalla/Desktop/Log/app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Example usage of logging
# logging.debug('This is a debug message')
# logging.info('This is an informational message')
# logging.warning('This is a warning message')
# logging.error('This is an error message')
# logging.critical('This is a critical message')

def encrypt_path(path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(path.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def decrypt_path(encrypted_path, key):
    iv = encrypted_path[:AES.block_size]
    ct = encrypted_path[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

replica_servers = [("127.0.0.1", 65442),("127.0.0.1", 65443),("127.0.0.1", 65444)]


def register():
    usr = input("Enter a new username: ")
    pwd = input("Enter a new password: ")
    database_cursor.execute("SELECT * FROM users WHERE username=%s", (usr,))
    if database_cursor.fetchone() is not None:
        print("The username or password is not valid!")
        logging.debug("Username %s or password is not valid", usr)
    else:
        pwd_hash = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
        database_cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (usr, pwd_hash))
        logging.critical("New user credentials were inserted into database")
        cnx.commit()
        print("A new user has been created successfully!")
        logging.info("New User was created with username : %s", usr)


        #generating public_keys & private_keys for user
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        sql = "INSERT INTO access_control (public_key, private_key, username, re, wr, delet, cre, rest,file_id) VALUES (%s, %s, %s,%s, %s, %s, %s, %s,%s)"
        logging.warning("The user %s has provided with an open access by default to all files !")
        val = (public_key.decode('utf-8'), private_key.decode('utf-8'), usr, 1,1,1,1,1,1)
        database_cursor.execute(sql, val)
        cnx.commit()

def login():
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
    def get_user_credentials():
        entered_username = input("Enter the username: ")
        entered_password = input("Enter the password: ")
        return entered_username, hashlib.sha256(entered_password.encode('utf-8')).hexdigest()

    def verify_user_credentials(usr, hashed_password):
        database_cursor.execute("SELECT password FROM users WHERE username=%s", (usr,))
        stored_user_data = database_cursor.fetchone()
        logging.critical("User password was used / taken from database")
        return stored_user_data and stored_user_data[0] == hashed_password

    # def fetch_user_priv_keys(user_name):
    #     database_cursor.execute("SELECT private_key FROM access_control WHERE username=%s and file_id=(select max(file_id) from access_control where username=%s)", (user_name,))
    #     result= database_cursor.fetchone()
    #     #print(result)
    #     return result[0]
    # def fetch_user_pub_keys(user_name):
    #     database_cursor.execute("SELECT public_key FROM access_control WHERE username=%s and file_id=(select max(file_id) from access_control where username=%s)", (user_name,))
    #     result= database_cursor.fetchone()
    #     #print(result)
    #     return result[0]

    def process_user_commands(user_name, command_start_time):
        y=command_start_time
        command_end_time = time.time()
        print(f"The total execution time is: {command_end_time - y:.2f} seconds")
        logging.info("Total execution time for the operations is : {:.2f} Seconds".format(command_end_time))


    def execute_user_command(username, command_start_time):
        x=command_start_time

        database_cursor.execute("select public_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)",(username, username))
        result = database_cursor.fetchone()[0]
        result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
        result = result.replace('\n-----END RSA PUBLIC KEY-----\n', '')
        public_key_str = result
        public_key_bytes = base64.b64decode(public_key_str)
        public_key = RSA.import_key(public_key_bytes)
        database_cursor.execute("select private_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)",(username, username))
        result = database_cursor.fetchone()[0]
            # result = result.replace('-----BEGIN PRIVATE KEY-----\n', '')
            # result = result.replace('\n-----END PRIVATE KEY-----\n', '')
        privateKeyString = result
        private_key = RSA.import_key(privateKeyString)
        while True:
                command = int(input("Enter an operation that you wish to perform (1. CREATE, 2. READ, 3. WRITE, 4. RESTORE, 5. DELETE 6. EXIT): "))
                if command == 1:
                    logging.info("User %s is creating a new file ", username)
                    message = username + ':create'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input("Enter a File Name: ")
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                    flag= True
                    file_id = int(client.recv(1024).decode('utf-8'))
                    while(flag):
                        set_permissions = input("Would you like to grant other users any access permissions? (y/n) ")
                        if set_permissions.lower() == 'y':
                            database_cursor.execute("SELECT username FROM users WHERE username != %s GROUP BY username",(username,))
                            rows = database_cursor.fetchall()
                            logging.info("Username are fetched from the database")
                            for i in rows:
                                print(i)
                            other_username = input("Which of the users listed above do you wish to grant access to? ")
                            database_cursor.execute("SELECT * FROM users WHERE username=%s", (other_username,))
                            if database_cursor.fetchone() is not None:
                                print(filename);
                                print(file_id)
                                print("Enter the permissions you want to grant (READ, WRITE, DELETE, CREATE, RESTORE): ")
                                logging.warning("The %s is trying to grant permissions to user %s to the file %s ", username, other_username, filename)
                                re = int(input())
                                wr = int(input())
                                delet = int(input())
                                cre = int(input())
                                rest = int(input())
                                database_cursor.execute("select public_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)", (other_username,other_username))
                                other_user_pub_key = database_cursor.fetchone()[0]
                                # print(other_user_pub_key);
                                database_cursor.execute("select private_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)", (other_username,other_username))
                                other_user_pri_key = database_cursor.fetchone()[0]
                                # print(other_user_pri_key);
                                database_cursor.execute("INSERT INTO access_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(other_user_pub_key,other_user_pri_key,other_username,re, wr, delet, cre, rest, file_id));
                                logging.info("the user %s now has Read:%s, write:%s, delete:%s, create:%s, restore:%s, set of permissions granted by user %s ", other_username ,re, wr, delet, cre, rest, username)
                                cnx.commit()
                                print("Would you like to grant access to any other users? (y/n)")
                                set_permissions = input()
                                if(set_permissions.lower()=='y'):
                                    flag = True
                                else:
                                    flag = False
                        else:
                            print("Moving to further operations")
                            flag = False
                elif command == 2:
                    message = username + ':read'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data_encrypted = client.recv(65536)
                    print("Using the RSA algorithm, the encrypted data is: ",data_encrypted)
                    cipher = PKCS1_OAEP.new(private_key)
                    data = cipher.decrypt(data_encrypted).decode('utf-8')
                    print("Using the user's RSA private key, the decrypted data is: ", data)
                    read_message = client.recv(1024)
                    print(read_message)
                    logging.info("The user %s has tried to read the data in file %s", username, filename)

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
                    if(write_acess == '1'):
                        data_encrypted = client.recv(1024)
                        print("Using the RSA algorithm, the encrypted data is: ", data_encrypted)
                        cipher = PKCS1_OAEP.new(private_key)
                        data = cipher.decrypt(data_encrypted).decode('utf-8')
                        print("The current content and the decrypted data using User's private key of RSA:", data)
                        new_data = input("Enter the new content that you would wish to add: ")
                        logging.info("the user %s has modified the content in file %s", username, filename)
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
                    logging.info("The file %s was restored by user %s", filename, username)

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
                    logging.info("The user %s has deleted the file %s", username, filename)
                else:
                    process_user_commands(username, x)
                    break
        else:
            print("The username or password is incorrect!")
        pass

    username, password_hash = get_user_credentials()
    if verify_user_credentials(username, password_hash):
        print("Login successful! Connecting to the server..")
        logging.warning("Username %s has logged in successfully & was now able to use the file system ", username)

        # user_private_key_pem = fetch_user_priv_keys(username)
        # user_public_key_pem = fetch_user_pub_keys(username)
        #
        # rsa_public_key = RSA.import_key(base64.b64decode(user_public_key_pem))
        # rsa_private_key = RSA.import_key(base64.b64decode(user_private_key_pem))
        command_start_time = time.time()

        execute_user_command(username, command_start_time)
    else:
        print("The username or password is incorrect!")
        logging.warning("Failed to validate the credentials for %s user with provided details", username)

def change_key(c, cnx):
    username = input("Enter the username: ")
    password = input("Enter the password: ")

    # Hashing the input password
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Check if the username exists and retrieve the stored password hash
    c.execute("SELECT password FROM users WHERE username=%s", (username,))
    result = c.fetchone()

    if result is None:
        print("This username does not exist!")
    else:
        stored_password_hash = result[0]
        if password_hash == stored_password_hash:
            print("Generating new pair of public and private keys")

            # Generate new RSA keys
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

            # Update the keys in the database
            sql = "UPDATE access_control SET public_key=%s, private_key=%s WHERE username=%s"
            val = (public_key.decode('utf-8'), private_key.decode('utf-8'), username)
            c.execute(sql, val)
            cnx.commit()
            print("New keys have been generated successfully!")
        else:
            print("The password is incorrect!")


#def createfile()
def create_file(username):
    try:
        request_filename = "Please send me the file name that you want to create"
        client.send(request_filename.encode('utf-8'))
        filename_encrypted = client.recv(1024).decode('utf-8')
        filename = filename_encrypted

        database_cursor.execute("SELECT cre FROM access_control WHERE username=%s and file_id=%s", (username, 1))
        access = database_cursor.fetchone()

        if access[0] == 1:
            aes_key = get_random_bytes(16)  # AES key for 128-bit encryption
            # Encrypt the file path
            encrypted_file_path = encrypt_path("/Users/saitejachalla/Desktop/PCS Project/" + filename + ".txt", aes_key)
            # When you need to use the file path, decrypt it
            decrypted_file_path = decrypt_path(encrypted_file_path, aes_key)

            with open(decrypted_file_path, 'w') as f:
            # file_path = "/Users/saitejachalla/Desktop/PCS Project/" + filename + ".txt"
            # with open(file_path, 'w') as file:
                data = "The file has been created successfully!"
                client.send(data.encode('utf-8'))

                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(transaction_time)

                sql_insert_file = "INSERT INTO files (filename, owner) VALUES (%s, %s)"
                val_insert_file = (filename, username)
                print("Inserting file into the database")
                database_cursor.execute(sql_insert_file, val_insert_file)
                cnx.commit()
                print("The file has been committed into the database!")

                database_cursor.execute("SELECT file_id FROM files WHERE filename=%s", (filename,))
                file_row = database_cursor.fetchone()
                file_id = file_row[0]
                client.send(str(file_id).encode('utf-8'))
                cnx.commit()

                database_cursor.execute("select public_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)", (username, username))
                other_user_pub_key = database_cursor.fetchone()[0]

                database_cursor.execute("select private_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)", (username, username))
                other_user_pri_key = database_cursor.fetchone()[0]

                database_cursor.execute("INSERT INTO access_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)", (other_user_pub_key, other_user_pri_key, username, 1, 1, 1, 1, 1, file_id))

                sql_insert_transaction = "INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)"
                val_insert_transaction = (username, filename, "create", transaction_time)
                database_cursor.execute(sql_insert_transaction, val_insert_transaction)
                cnx.commit()

            for replica_server in replica_servers:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect(replica_server)
                    request = ('create', filename, '')
                    s.sendall(pickle.dumps(request))

            replica_message = {"filename": filename, "operation": "create"}
        else:
            print("You do not have the permission!")

    except Exception as e:
        print("Error in creating file:", e)

def fetch_file_content(usr):
    prompt_message = "Please send the file name"
    client.send(prompt_message.encode('utf-8'))
    encrypted_file_name = client.recv(1024).decode('utf-8')
    requested_filename = encrypted_file_name  # Assuming the filename is directly received

    query = """SELECT private_key FROM access_control 
               WHERE username=%s and file_id=(select max(file_id) from access_control where username=%s)"""
    database_cursor.execute(query, (usr, usr))
    private_key_data = database_cursor.fetchone()[0]
    user_private_key = RSA.import_key(private_key_data)
    print(private_key_data)
    cipher = PKCS1_OAEP.new(private_key_data)

    try:
        aes_key = get_random_bytes(16)  # AES key for 128-bit encryption
            # Encrypt the file path
        encrypted_file_path = encrypt_path("/Users/saitejachalla/Desktop/PCS Project/" + requested_filename + ".txt", aes_key)
            # When you need to use the file path, decrypt it
        decrypted_file_path = decrypt_path(encrypted_file_path, aes_key)

        with open(decrypted_file_path, 'r') as f:
        #with open("/Users/saitejachalla/Desktop/PCS Project/" + requested_filename + ".txt", 'r') as file:
            file_content = f.read()
            encryption_key_query = """SELECT public_key FROM access_control 
                                      WHERE username=%s and file_id=(select max(file_id) from access_control where username=%s"""
            database_cursor.execute(encryption_key_query, (usr, usr))
            public_key_data = database_cursor.fetchone()[0].replace('-----BEGIN RSA PUBLIC KEY-----\n', '').replace('\n-----END RSA PUBLIC KEY-----\n', '')
            user_public_key = RSA.import_key(base64.b64decode(public_key_data))

            encryption_cipher = PKCS1_OAEP.new(user_public_key)
            encrypted_data = encryption_cipher.encrypt(file_content.encode('utf-8'))

            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            client.send(encrypted_data)

            transaction_log_query = """INSERT INTO transactions 
                                       (username, file_name, transaction_type, transaction_time) 
                                       VALUES (%s, %s, %s, %s)"""
            database_cursor.execute(transaction_log_query, (usr, requested_filename, "read", current_time))
            cnx.commit()

            success_message = "The file has been read successfully!"
            client.send(success_message.encode('utf-8'))
    except Exception as e:
        error_message = "You are not authorized to access the file or the file does not exist!"
        client.send(error_message.encode('utf-8'))
        print('File not found or access denied.', e)

def write_file(username):
    try:
        # Request the filename from the client
        client.send("Please send me the file name that you want to perform write operation on:".encode('utf-8'))
        filename_encrypted = client.recv(1024).decode('utf-8')
        filename = filename_encrypted

        # Check if the file exists and the user has write access
        aes_key = get_random_bytes(16)  # AES key for 128-bit encryption
            # Encrypt the file path
        encrypted_file_path = encrypt_path("/Users/saitejachalla/Desktop/PCS Project/" + filename + ".txt", aes_key)
            # When you need to use the file path, decrypt it
        decrypted_file_path = decrypt_path(encrypted_file_path, aes_key)

        with open(decrypted_file_path, 'r+') as f:
        #with open(f"/Users/saitejachalla/Desktop/PCS Project/{filename}.txt", 'r+') as f:
            database_cursor.execute("SELECT file_id FROM files WHERE filename=%s", (filename,))
            file_id = database_cursor.fetchone()[0]

            database_cursor.execute("SELECT wr FROM access_control WHERE username=%s AND file_id=%s", (username, file_id))
            result = database_cursor.fetchone()

            if result is not None:
                write_access = result[0]
                print(write_access)
                client.send(str(write_access).encode('utf-8'))

                if write_access == 1:
                    # Acquire file lock
                    fcntl.flock(f, fcntl.LOCK_EX)

                    # Read file content and encrypt with user's public key
                    data = f.read()
                    database_cursor.execute("SELECT public_key FROM access_control WHERE username=%s AND file_id=(SELECT MAX(file_id) FROM access_control WHERE username=%s)", (username, username))
                    result = database_cursor.fetchone()[0]
                    result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '').replace('\n-----END RSA PUBLIC KEY-----\n', '')
                    public_key_bytes = base64.b64decode(result)
                    public_key = RSA.import_key(public_key_bytes)
                    cipher = PKCS1_OAEP.new(public_key)
                    data_encrypted = cipher.encrypt(data.encode('utf-8'))

                    # Send encrypted data to the client
                    client.send(data_encrypted)

                    # Receive new data from the client and update the file
                    data2 = client.recv(1024)
                    new_data = data2.decode('utf-8')
                    f.seek(0, os.SEEK_END)
                    f.write(new_data)
                    f.truncate()

                    # Release lock on the file
                    fcntl.flock(f, fcntl.LOCK_UN)

                    # Replicate data to replica servers
                    replication_data = new_data.encode('utf-8')
                    for replica_server in replica_servers:
                        with socket(AF_INET, SOCK_STREAM) as s:
                            s.connect(replica_server)
                            request = ('write', filename, replication_data)
                            s.sendall(pickle.dumps(request))

                    # Log the transaction
                    transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    database_cursor.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s, %s)", (username, filename, "write", transaction_time))
                    cnx.commit()

                    # Notify the client about successful file write
                    write_message = "The file has been written successfully!"
                    client.send(write_message.encode('utf-8'))
                else:
                    # Notify the client about lack of write permission
                    write_message = "You do not have the permission to write!"
                    client.send(write_message.encode('utf-8'))
            else:
                # Notify the client about authorization failure
                write_access = 0
                print(write_access)
                client.send(str(write_access).encode('utf-8'))
                write_message = "You are not authorized to access the file or the file does not exist!"
                client.send(write_message.encode('utf-8'))

    except Exception as e:
        # Notify the client about file not found or authorization failure
        write_message = "You are not authorized to access the file or the file does not exist!"
        client.send(write_message.encode('utf-8'))
        print('File not found.', e)

def restore_file(username, c, cnx, client, replica_servers):
    prompt_message = "Please send me the file name that you want to restore"
    client.send(prompt_message.encode('utf-8'))
    filename = client.recv(1024).decode('utf-8')

    src_path = f"/Users/saitejachalla/Desktop/PCS Project/restore_files/{filename}.txt"
    dest_path = f"/Users/saitejachalla/Desktop/PCS Project/{filename}.txt"

    try:
        # Check user's permission to restore
        c.execute("SELECT rest FROM access_control WHERE username=%s AND file_id=(SELECT file_id FROM files WHERE filename=%s)", (username, filename))
        access = c.fetchone()

        if access and access[0] == 1:
            # Copy file from backup to original location
            shutil.copy(src_path, dest_path)

            # Log the transaction
            transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s, %s)", (username, filename, "restore", transaction_time))
            cnx.commit()

            # Send success message
            restore_message = "The file has been restored successfully!"
            client.send(restore_message.encode('utf-8'))

            # Replicate to other servers
            replicate_to_servers(filename, src_path, replica_servers)
        else:
            client.send("You do not have the permission to restore!".encode('utf-8'))

    except Exception as e:
        client.send("You are not authorised to access the file or the file does not exist!".encode('utf-8'))
        print(f'File not found or access denied: {e}')

def replicate_to_servers(filename, src_path, replica_servers):
    with open(src_path, 'rb') as file:
        data = file.read()
        for server in replica_servers:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.connect(server)
                request = ('restore', filename, data)
                s.sendall(pickle.dumps(request))



def delete_file(username, database_cursor, cnx, client, replica_servers):
    prompt_message = "Please send me the file name that you want to delete"
    client.send(prompt_message.encode('utf-8'))
    filename = client.recv(1024).decode('utf-8')

    src_path = f"/Users/saitejachalla/Desktop/PCS Project/{filename}.txt"
    dest_path = f"/Users/saitejachalla/Desktop/PCS Project/restore_files/{filename}.txt"

    try:
        # Check if user has delete permissions
        database_cursor.execute("select file_id from files where filename=%s", (filename,))
        file_id = database_cursor.fetchone()[0]
        print(file_id)
        database_cursor.execute("SELECT delet FROM access_control WHERE username=%s and file_id=%s", (username, file_id))
        access = database_cursor.fetchone()

        if(access[0] == 1):
            # Move the file to restore folder instead of deleting
            shutil.move(src_path, dest_path)

            # Log the transaction
            transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            database_cursor.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s, %s)", (username, filename, "delete", transaction_time))
            cnx.commit()

            # Send success message
            delete_message = "The file has been deleted successfully!"
            client.send(delete_message.encode('utf-8'))

            # Notify replica servers
            notify_replica_servers('delete', filename, replica_servers)
        else:
            client.send("You do not have the permission to delete!".encode('utf-8'))

    except FileNotFoundError:
        client.send("File not found".encode('utf-8'))
    except Exception as e:
        client.send("An error occurred".encode('utf-8'))
        print(f'Error: {e}')

def notify_replica_servers(operation, filename, replica_servers):
    for server in replica_servers:
        with socket(AF_INET, SOCK_STREAM) as s:
            s.connect(server)
            request = (operation, filename, '')
            s.sendall(pickle.dumps(request))

# Usage example
# Assuming 'c' is your database cursor, 'cnx' is your database connection, 'client' is the client socket, and 'replica_servers' is a list of replica server addresses
# delete_file('username', c, cnx, client, replica_servers)



server_port = 65525
cnx = pymysql.connect(host='127.0.0.1', user='root', password='Saiteja@22', db='pcsproj')

database_cursor = cnx.cursor();
print("1. Server 2. Client")
choose=int(input())
if(choose==2):
    client_address = '127.0.0.1'
    client = socket(AF_INET, SOCK_STREAM)
    client.connect((client_address, server_port))
    # print("Select the server you want to connect with: 1.Primary server 2.Replica server1 3.Replica server2 4.Replica server3")
    # d = int(input())
    # if(d==1):
    #     print("Connection Sucess with Primary server!!")
    # elif(d==2):
    #     print("Connection Sucess with Replica server1!!")
    # elif(d==3):
    #     print("Connection Sucess with Replica server2!!")
    # elif(d==4):
    #     print("Connection Sucess with Replica server3!!")
    # else:
    #     print("Please select valid server to connect")
    client.send("Client connected and sending requests".encode('utf-8'))
    data = client.recv(1024)
    print(data.decode('utf-8'))
    while True:
        print("Please choose an action that you want to perform")
        print("1 - Register with server")
        print("2 - Login and make connection with the server")
        print("3- Change Key")
        print()
    # create_connection()
    #database connection
        try:
            choice = int(input())
            if choice == 1:
                register()
            elif choice==2:
                login()
            elif choice==3:
                change_key();
            else:
                exit(0)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Username or password is incorrect!")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist!")
            else:
                print(err)
else:
    server_address = '127.0.0.1'
    serv = socket(AF_INET, SOCK_STREAM)
    serv.bind((server_address, server_port))
    serv.listen(25)
    client, address = serv.accept()
    data = client.recv(1024)
    print(data.decode('utf-8'))
    client.send("Hi I am server".encode('utf-8'))
    while True:
        try:
            data = client.recv(1024).decode('utf-8')
            username, command = data.split(':')
            print(username)
            print(command)
            if command == "create":
                create_file(username)
            elif command == "read":
                fetch_file_content(username)
            elif command == "write":
                print("sai")
                write_file(username)
            elif command == "restore":
                restore_file(username)
            elif command == "delete":
                delete_file(username)
            else:
                print("Sorry the operation is invalid!")
        except:
            pass
    # serv.close()

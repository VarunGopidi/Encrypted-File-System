#rough code functions
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from crypto.Hash import SHA256
from crypto.Signature import PKCS1_v1_5

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
        with open(f"{requested_filename}.txt", 'r') as file:
            file_content = file.read()
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
            db_connection.commit()

            success_message = "File read successfully!"
            client.send(success_message.encode('utf-8'))
    except Exception as e:
        error_message = "You are not authorized to access the file or the file does not exist"
        network_client.send(error_message.encode('utf-8'))
        print('File not found or access denied.', e)

# Usage example
# Assuming 'database_cursor', 'db_connection', and 'network_client' are initialized
# fetch_file_content("username")

import os
import socket
import shutil
import pickle
from datetime import datetime
import mysql.connector

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
            restore_message = "File restored successfully"
            client.send(restore_message.encode('utf-8'))

            # Replicate to other servers
            replicate_to_servers(filename, src_path, replica_servers)
        else:
            client.send("You don't have permission to restore!".encode('utf-8'))

    except Exception as e:
        client.send("You are not authorised to access the file or the file does not exist".encode('utf-8'))
        print(f'File not found or access denied: {e}')

def replicate_to_servers(filename, src_path, replica_servers):
    with open(src_path, 'rb') as file:
        data = file.read()
        for server in replica_servers:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.connect(server)
                request = ('restore', filename, data)
                s.sendall(pickle.dumps(request))

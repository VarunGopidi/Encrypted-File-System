import os
import socket
import shutil
import pickle
from datetime import datetime
import mysql.connector

def restore_file(username):
try:
    with open("C:/Users/kavya/OneDrive/Desktop/pcs_proj/" + filename + ".txt", 'r+') as f:
        c.execute("SELECT file_id FROM files WHERE filename=%s", (filename,))
        file_id = c.fetchone()[0]
        c.execute("SELECT rest FROM access_control WHERE username=%s and file_id=%s", (username,file_id))
        access = c.fetchone()

        if (access[0] == 1):
            src_path = "C:/Users/kavya/OneDrive/Desktop/pcs_proj/"+ filename + ".txt"
            dest_path = "C:/Users/kavya/OneDrive/Desktop/pcs_proj1/restore_files"+ filename + ".txt"
            shutil.copy(src_path, dest_path)
            transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "restore", transaction_time))
            cnx.commit()
            restore_message = "File restored successfully"
            client.send(restore_message.encode('utf-8'))
            data = f.read()
            replication_data = data.encode('utf-8')

            for replica_server in replica_servers:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect(replica_server)
                    request = ('restore', filename, replication_data)
                    s.sendall(pickle.dumps(request))
        else:
            restore_message = "You don't have permission to restore!"
            client.send(restore_message.encode('utf-8'))
except Exception as e:
    restore_message = "You are not authorized to access the file or the file does not exist"
    client.send(restore_message.encode('utf-8'))
    print('File not found.', e)


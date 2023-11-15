import os
import socket
import shutil
import pickle
from datetime import datetime
import mysql.connector

def restore_file(username):
    try:
        x = "please send me the file name that you want to restore "
        client.send(x.encode('utf-8'))
        filename_encrypted = client.recv(1024).decode('utf-8')
        filename = filename_encrypted
        cnx = mysql.connector.connect(user='root', password='Hello@12345', host='127.0.0.1', database='db')
        c = cnx.cursor()
        c.execute("select file_id from files where filename=%s", (filename,))
        file_id = c.fetchone()[0]
        c.execute("SELECT rest FROM acess_control WHERE username=%s and file_id=%s", (username,file_id))
        access = c.fetchone()
        if (access[0] == 1):
            src_path = "C:/Users/kavya/OneDrive/Desktop/pcs_proj/"+ filename + ".txt"
            dest_path = "C:/Users/kavya/OneDrive/Desktop/pcs_proj1/restore_files"+ filename + ".txt"
            shutil.copy(src_path, dest_path)
            transaction_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "restore", transaction_time))
            cnx.commit()
            restore_message = "File restored successfully"
            client.send(restore_message.encode('utf-8'))
            with open(dest_path, 'r') as f:
                data = f.read()
                replication_data = data.encode('utf-8')
                for replica_server in replica_servers:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s
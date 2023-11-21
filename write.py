import socket
import os
import fcntl
import rsa
import base64
import pickle
import datetime
from pkcs1.hazmat.primitives.asymmetric import padding


def write_file(username):
    x = "Please send me the file name to perform write operation ";
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted;
    try:
        with open("C:/Users/kavya/OneDrive/Desktop/pcs_proj/" + filename + ".txt", 'r+') as f:
            c.execute("select file_id from files where filename=%s",(filename,))
            file_id=c.fetchone()[0]
            c.execute("SELECT wr FROM access_control WHERE username=%s and file_id=%s", (username,file_id))
            result = c.fetchone()
            if result is not None:
                write_access=result[0]
                print(write_access)
                client.send(str(write_access).encode('utf-8'))
                if (write_access == 1):
                    fcntl.flock(f, fcntl.LOCK_EX)
                    data = f.read()
                    c.execute("select public_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)",(username, username))
                    result = c.fetchone()[0]
                    result = result.replace('-----BEGIN RSA PUBLIC KEY-----\n', '')
                    result = result.replace('\n-----END RSA PUBLIC KEY-----\n', '')
                    public_key_str = result
                    public_key_bytes = base64.b64decode(public_key_str)
                    public_key = rsa.import_key(public_key_bytes)
                    cipher = padding.OAEP(mgf=padding.MGF1(algorithm=11289220), algorithm=hashes.SHA256, label=None)
                    x = "Please send me the data to be written ";
                    client.send(x.encode('utf-8'))
                    data_encrypted = client.recv(1024).decode('utf-8')
                    ciphertext = rsa.decrypt(base64.b64decode(data_encrypted), private_key,
                                              cipher)
                    new_data = ciphertext.decode('utf-8')
                    f.seek(0, os.SEEK_END)
                    f.write(new_data)
                    f.truncate()
                    write_message = "File written successfully";
                    client.send(write_message.encode('utf-8'))
                    # release lock on file
                    fcntl.flock(f, fcntl.LOCK_UN)
                    replication_data = new_data.encode('utf-8')
                    for replica_server in replica_servers:
                        with socket(AF_INET, SOCK_STREAM) as s:
                            s.connect(replica_server)
                            request = ('write', filename, replication_data)
                            s.sendall(pickle.dumps(request))
                    transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    c.execute(
                        "INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",
                        (username, filename, "write", transaction_time))
                    cnx.commit()
                else:
                    write_message = "You don't have permission to write!";
                    client.send(write_message.encode('utf-8'))
            else:
                write_access=0
                print(write_access)
                client.send(str(write_access).encode('utf-8'))
                write_message = "You are not authorised to access the file";
    except Exception as e:
        write_message = "You are not authorised to access the file or the file does not exist ";
        client.send(write_message.encode('utf-8'))
        print('File not found.', e)
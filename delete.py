def delete_file(username):
    x = "please send me the file name that you want to delete "
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted
    # filepath = os.path.join("Users","dineshgadu", "Desktop","PCS Project", filename,".txt")
    try:
        # with open("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt", 'r') as f:
    # c.execute("SELECT * FROM transactions WHERE filename=?", (filename,))
    # if c.fetchone() is
    # if os.path.exists(filepath):
        c.execute("select file_id from files where filename=%s", (filename,))
        file_id = c.fetchone()[0]
        print(file_id)
        c.execute("SELECT delet FROM access_control WHERE username=%s and file_id=%s", (username,file_id))
        access = c.fetchone()
        # print(access)
        if (access[0] == 1):
            src_path = "/Users/saitejachalla/Desktop/PCS Project/" + filename + ".txt"
            dest_path = "/Users/saitejachalla/Desktop/PCS Project/restore_files/" + filename + ".txt"
            shutil.move(src_path, dest_path)
            # os.remove("/Users/dineshgadu/Desktop/PCS Project/" + filename + ".txt")
            transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)",(username, filename, "delete", transaction_time))
            cnx.commit()
            delete_message = "File deleted!"
            client.send(delete_message.encode('utf-8'))
            for replica_server in replica_servers:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect(replica_server)
                    request = ('delete', filename, '')
                    s.sendall(pickle.dumps(request))
        else:
            delete_message = "You don't have permission to perform delete operation!"
            client.send(delete_message.encode('utf-8'))
    except Exception as e:
        delete_message = "You are not authorised to access the file or the file does not exist "
        client.send(delete_message.encode('utf-8'))
        print('File not found.', e)

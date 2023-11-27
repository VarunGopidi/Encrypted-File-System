def create_file(username):
    x = "please send me the file name that you wanted to create "
    client.send(x.encode('utf-8'))
    filename_encrypted = client.recv(1024).decode('utf-8')
    filename = filename_encrypted
    # filepath = "/Users/dineshgadu/Desktop/PCS Project" + filename + ".txt"
    #
    # if not os.path.exists("/Users/dineshgadu/Desktop/PCS Project"):
    #     os.makedirs("/Users/dineshgadu/Desktop/PCS Project")
    try:
        c.execute("SELECT cre FROM access_control WHERE username=%s and file_id=%s", (username,1))
        access = c.fetchone()
        # print(access)
        if (access[0] == 1):
            with open("/Users/saitejachalla/Desktop/PCS Project/"+filename+".txt", 'w') as f:
                data="File created successfully!"
                # file_id = c.lastrowid
                client.send(data.encode('utf-8'))
                transaction_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(transaction_time)

                sql1 = "INSERT INTO files (filename,owner) VALUES (%s, %s)"
                val1 = (filename, username)
                print("inserting...")
                c.execute(sql1, val1)
                print("inserted...")
                cnx.commit()
                print("commited...")
                c.execute("SELECT file_id FROM files WHERE filename=%s", (filename,))
                row = c.fetchone()
                file_id = row[0]
                print(file_id)
                client.send(str(file_id).encode('utf-8'))
                cnx.commit()
                c.execute("select public_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)",(username, username))
                other_user_pub_key = c.fetchone()[0]
                # print(other_user_pub_key);
                c.execute("select private_key from access_control where username=%s and file_id=(select max(file_id) from access_control where username=%s)",(username, username))
                other_user_pri_key = c.fetchone()[0]
                # print(other_user_pri_key);
                c.execute("INSERT INTO access_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(other_user_pub_key, other_user_pri_key, username, 1, 1, 1, 1, 1, file_id));
                sql = "INSERT INTO transactions (username, file_name, transaction_type, transaction_time) VALUES (%s, %s, %s,%s)"
                val = (username, filename, "create", transaction_time)
                c.execute(sql, val)
                cnx.commit()
            for replica_server in replica_servers:
                with socket(AF_INET, SOCK_STREAM) as s:
                    s.connect(replica_server)
                    request = ('create', filename,'')
                    s.sendall(pickle.dumps(request))
            #send message to replica
            replica_message = {"filename": filename, "operation": "create"}

            # replica_socket.close()
        else:
            print("You don't have permission!")
    except Exception as e:
        print("Error creating file:", e)

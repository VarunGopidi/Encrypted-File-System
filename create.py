def create_file(username):
    try:
        request_filename = "Please send me the file name that you want to create "
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

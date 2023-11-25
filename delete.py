def delete_file(username):
    prompt_message = "Please send me the file name that you want to delete"
    client.send(prompt_message.encode('utf-8'))
    filename = client.recv(1024).decode('utf-8')

    src_path = f"/Users/saitejachalla/Desktop/PCS Project/{filename}.txt"
    dest_path = f"/Users/saitejachalla/Desktop/PCS Project/restore_files/{filename}.txt"

    try:
        # Check if user has delete permissions
        database_cursor.execute("SELECT delet FROM access_control WHERE username=%s AND file_id=(SELECT file_id FROM files WHERE filename=%s)", (username, filename))
        access = database_cursor.fetchone()

        if access and access[0] == 1:
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
            exit(0)

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

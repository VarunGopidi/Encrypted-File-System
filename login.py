import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from crypto.Hash import SHA256
from crypto.Signature import PKCS1_v1_5
from log_activity import log_activity

def login(database_cursor, database_connection, network_client):
    def get_user_credentials():
        entered_username = input("Enter user_name: ")
        entered_password = input("Enter password: ")
        return entered_username, hashlib.sha256(entered_password.encode('utf-8')).hexdigest()

    def verify_user_credentials(usr, hashed_password):
        database_cursor.execute("SELECT password FROM users WHERE username=%s", (user_name,))
        stored_user_data = database_cursor.fetchone()
        return stored_user_data and stored_user_data[0] == hashed_password

    def fetch_user_keys(user_name):
        database_cursor.execute("SELECT public_key, private_key FROM access_control WHERE username=%s ORDER BY file_id DESC LIMIT 1", (user_name,))
        return database_cursor.fetchone()


    def get_user_command():
        while True:
            try:
                user_command = int(input("Enter a command (1. Create a File, 2. Read a File, 3. Write to File, 4. Restore a File, 5. Delete a File, 6. Exit from Application): "))
                if 1 <= user_command <= 6:
                    return user_command
                else:
                    print("Invalid command. Please enter a valid command.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    
    def log_exit(user_name, timer)




    def process_user_commands(user_name):
        command_start_time = time.time()
        log_activity(user_name, "as logged into File System")
        while True:
            user_command = get_user_command()
            if user_command == 6:
                command_end_time = time.time()
                msg = f"Total execution time: {command_end_time - command_start_time:.2f} seconds"
                # print(f"Total execution time: {command_end_time - command_start_time:.2f} seconds")
                print(msg)
                log_activity(user_name, "as exited the file system !")
                log_activity(user_name, msg)
                
                break
            else:
                execute_user_command(user_name, user_command)

    def execute_user_command(user_name, command_id):
        while True:
                command =get_user_command() # This queery will repeat if the user first selects 1 in process user commands and execute user commands again generates this query
                if command == 1:
                    message = username + ':create'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input("Enter a file name: ")
                    filename_encrypted = filename.encode('utf-8')
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
                    flag=1
                    file_id = int(client.recv(1024).decode('utf-8'))
                    log_activity(user_name, {"as created a new file %s in application ", filename} )
                    while(flag):

                        set_permissions = input("Do you want to set permissions for other users? (y/n) ")
                        if set_permissions.lower() == 'y':
                            other_username = input("Enter the username of the user you want to give permissions to: ")
                            # c.execute("select public_key from acess_control where username=%s",(other_username,))
                            # other_user_pub_key = c.fetchone()
                            # other_user_pri_key =
                            users =  c.execute("SELECT * FROM users WHERE username=%s", (other_username,))
                            print(users)
                            if c.fetchone() is not None:
                                print(filename);
                                print(file_id)
                                # c.execute("SELECT file_id FROM files WHERE filename=%s", ('kp',))
                                # row = c.fetchone()
                                # file_id = row[0]
                                # print(row)
                                print("Enter the permissions you want to grant (read, write, delete, create, restore): ")
                                print("Enter "1" for yes and "0" for no correspondingly in order")
                                re = int(input())
                                wr = int(input())
                                delet = int(input())
                                cre = int(input())
                                rest = int(input())
                                permissions = f"Read:{re.boolean()} Write:{wr.boolean()} delete:{delet.boolean()} create:{cre.boolean()}, restore:{rest.boolean()}"
                                c.execute("select public_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (other_username,other_username))
                                other_user_pub_key = c.fetchone()[0]
                                # print(other_user_pub_key);
                                c.execute("select private_key from acess_control where username=%s and file_id=(select max(file_id) from acess_control where username=%s)", (other_username,other_username))
                                other_user_pri_key = c.fetchone()[0]
                                # print(other_user_pri_key);
                                c.execute("INSERT INTO acess_control (public_key,private_key,username,re,wr,delet,cre,rest,file_id) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)",(other_user_pub_key,other_user_pri_key,other_username,re, wr, delet, cre, rest, file_id));
                                # c.execute("UPDATE acess_control SET re = %s,wr = %s,delet = %s,cre = %s,rest = %s,file_id = %s where username=%s", (re, wr, delet, cre, rest, file_id,other_username))
                                cnx.commit()
                                msg = "as provided %s user to access %s with permissions to %s ", other_username, filename, permissions
                                log_activity(user_name, msg)
                                print("do you want to give access to more users? Y/N")
                                set_permissions=input()
                                if(set_permissions.lower()=='y'):
                                    flag=1
                                else:
                                    flag=0
                        else:
                            print("Okay!!")
                elif command == 2:
                    
                    message = username + ':read'
                    client.send(message.encode('utf-8'))
                    sample = client.recv(1024).decode('utf-8')
                    print(sample)
                    filename = input()
                    filename_encrypted = filename.encode('utf-8')

                    client.send(filename_encrypted)
                    data_encrypted = client.recv(65536)
                    print("The encrypted data using RSA algorithm: ",data_encrypted)
                    cipher = PKCS1_OAEP.new(private_key)
                    data = cipher.decrypt(data_encrypted).decode('utf-8')
                    print("The Decrypted data using User's private key of RSA:", data)
                    read_message = client.recv(1024)
                    print(read_message)
                    log_activity(username, {"read the file %s", filename})


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
                    if(write_acess==1):
                        data_encrypted = client.recv(1024)
                        print("The encrypted data using RSA algorithm: ", data_encrypted)
                        cipher = PKCS1_OAEP.new(private_key)
                        data = cipher.decrypt(data_encrypted).decode('utf-8')
                        print("The Current content and Decrypted data using User's private key of RSA:", data)
                        new_data = input("Enter new content that you want to add: ")
                        log_activity(username, {"has made new writings to file %s with data %s", filename, new_data})
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
                    log_activity(username,"{has restored a file %s", filename})
                    client.send(filename_encrypted)
                    data = client.recv(1024)
                    print(data)
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
                    log_activity(username, {"deleted a filenamed as %s", filename})
                else:
                    end_time = time.time()
                    execution_time = end_time - start_time
                    print("Total execution time: {:.2f} seconds".format(execution_time))
                    log_activity(username, "Total execution time: {:.2f} seconds".format(execution_time))
                    exit(0)
        else:
            print("Incorrect Username or Password")
        pass

    username, password_hash = get_user_credentials()
    if verify_user_credentials(username, password_hash):
        print("Login successful! Connecting to the server...")
        log_activity(username, "has logged into the system!")
        user_public_key_pem, user_private_key_pem = fetch_user_keys(username)

        rsa_public_key = RSA.import_key(base64.b64decode(user_public_key_pem))
        rsa_private_key = RSA.import_key(base64.b64decode(user_private_key_pem))

        process_user_commands(username)
    else:
        print("Incorrect Username or Password!")
        log_activity(username, "has attempeted to login into the file system")

# Usage example
# Assuming 'database_cursor' is your database cursor, 'database_connection' is your database connection,
# and 'network_client' is a network client
# login(database_cursor, database_connection, network_client)

import socket
import pickle
import os

main_server = ("127.0.0.1", 65435)

#constants
PORT = 65442
DIR_PATH = "C:/Users/kavya/OneDrive/Desktop/pcs_proj1"


#file operations

def create_file(filepath):
    try:
        if not os.path.exists(DIR_PATH):
            os.makedirs(DIR_PATH)
        with open(filepath, 'w') as file:
            file.write('')
    except Exception as e:
        logger.error(f"Error - creating file: {e} ")

def write_to_file(filepath, data):
    try:
        with open(filepath, 'a') as file:
            file.write(data.decode('utf-8'))
    except Exception as e:
        logger.error(f"Error - writing to file: {e}")

def delete_file(filepath):
    try:
        os.remove(filepath)
    except Exception as e:
        logger.error(f"Error - deleting file: {e}")



def handle_request(request):
    operation, args, data = request
    filepath = os.path.join(DIR_PATH, args +".txt")

    if operation == 'create':
        create_file(filepath)
        return "The created file has been replicated successfully in Replica-1"
    elif operation == 'write':
        filename = args
        filepath = os.path.join(DIR_PATH, filename + ".txt")
        with open(filepath, 'a') as file:
            file.write(data.decode('utf-8'))
        return "The file is updated successfully in Replica-1"
    elif operation == 'restore':
        filename = args
        filepath = os.path.join(DIR_PATH, filename + ".txt")
        with open(filepath, 'a') as file:
            file.write(data.decode('utf-8'))
        return "The file is restored sucessfully in Replica-1"
    elif operation == 'delete':
        delete_file(filepath)
        return "The file is deleted successfully in Replica-1"
    else:
        return "Invalid operation"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Soc:
    Soc.bind(("127.0.0.1", PORT))
    Soc.listen()
    while True:
        conn, addr = Soc.accept()
        with conn:
            print('Connected by', addr)
            data = conn.recv(1024)
            if not data:
                break
            request = pickle.loads(data)
            response = handle_request(request)
            print(response)
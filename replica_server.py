import socket
import pickle
import os

main_server = ("127.0.0.1", 65435)

PORT = 65442

DIR_PATH = "C:/Users/kavya/OneDrive/Desktop/pcs_proj1"

def handle_request(request):
    operation, args, data = request
    if operation == 'create':
        filename = args
        filepath = os.path.join(DIR_PATH, filename + ".txt")
        if not os.path.exists(DIR_PATH):
            os.makedirs(DIR_PATH)
        with open(filepath, 'w') as file:
            file.write('')
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
        filename = args
        filepath = os.path.join(DIR_PATH, filename + ".txt")
        os.remove(filepath)
        return "The file is deleted successfully in Replica-1"
    else:
        return "Invalid operation"
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as x:
    x.bind(("127.0.0.1", PORT))
    x.listen()
    while True:
        conn, addr = x.accept()
        with conn:
            print('Connected by', addr)
            data = conn.recv(1024)
            if not data:
                break
            request = pickle.loads(data)
            response = handle_request(request)
            print(response)
#rough code functions


import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def register(c, cnx):
    name = input("Enter a new username: ")
    pwd = input("Enter a strong password: ")

    try:
        c.execute("SELECT * FROM users WHERE username=%s", (name,))
        if c.fetchone():
            print("Username already exists")
            return

        # Hashing password using bcrypt
        pwd_hash = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())

        c.execute("INSERT INTO users (name, pwd) VALUES (%s, %s)", (name, pwd_hash))
        cnx.commit()
        print("A new user created successfully.")

        # Generate RSA keys
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

        # Insert keys into database
        sql = """INSERT INTO access_control (public_key, private_key, username, read, write, delete, create, restore, file_id)
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        val = (public_key.decode('utf-8'), private_key.decode('utf-8'), name, 1, 1, 1, 1, 1, 1)
        c.execute(sql, val)
        cnx.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        cnx.rollback()

# Usage
# Assuming 'c' is your cursor and 'cnx' is your database connection
# register(c, cnx)

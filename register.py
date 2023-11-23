#import bcrypt
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def register():
    usr = input("Enter new username: ")
    pwd = input("Enter new password: ")
    database_cursor.execute("SELECT * FROM users WHERE username=%s", (usr,))
    if database_cursor.fetchone() is None:
        print("Invalid Username or Password")
    else:
        pwd_hash = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
        database_cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (usr, pwd_hash))
        cnx.commit()
        print("New user created successfully")

        #generating public_keys & private_keys for user
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        sql = "INSERT INTO access_control (public_key, private_key, username, re, wr, delet, cre, rest,file_id) VALUES (%s, %s, %s,%s, %s, %s, %s, %s,%s)"
        val = (public_key.decode('utf-8'), private_key.decode('utf-8'), usr, 0,0,0,0,0,0)
        database_cursor.execute(sql, val)
        cnx.commit()

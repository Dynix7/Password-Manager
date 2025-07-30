import argon2
#https://argon2-cffi.readthedocs.io/en/stable/api.html

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import sys
import os
#I'll add a GUI if i feel like it lol

#haha guys im aura farming by making insecure password manager

#Where the data is saved
storage = "storage.bin"

#Variable for seeing if the database is empty
empty = True


#HM OK CHAT ACTUALLY IT GIVES THE BASE64 AND NOT ACTUAL BYTES SO CHAT WAIT A SEC
#This generates the 32 byte key from the password using argon2
def getKey(password=None, salt=None):

    #Prompts for a password if one isn't given
    if password == None:
        password = input("Enter Password: ")

    #Turns the string to bytes
    password = password.encode()


    #Generate random 16 byte salt if none provided
    if salt == None:
        salt = get_random_bytes(16)

    #Just using default parameters for time, memory, and parallelism listed on documentation with ID type being the most secure
    #  this function DIRECTLY GIVES THE 32bytes and not base64encoded
    
    key = argon2.low_level.hash_secret_raw(password, salt, time_cost=3, memory_cost=65536,
    parallelism=4, hash_len=32, type=argon2.low_level.Type.ID)


    return key, salt



def encrypt(key, message):

    #Generates the Nonce/IV (basically random bytes to ensure every encryption of the same data is different, kinda like the salt)
    nonce = get_random_bytes(16)

    #Convert to json then to bytes
    message = json.dumps(message)
    message = message.encode()


    #sets up the cipher with the key, aes mode, and nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)


    #generates the ciphertext and a tag (verification basically)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return ciphertext, tag, nonce



def decrypt(ciphertext, tag, nonce, password, salt):

    key, salt = getKey(password, salt)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    message = cipher.decrypt_and_verify(ciphertext, tag)

    message = message.decode()
    message = json.loads(message)

    return message



password = input("Enter Master Password: ")



#REMINDER ORDER OF DATA: SALT, TAG, NONCE, CIPHERTEXT
#ALSO THE ACTUAL LOGINS AND STUFF ARE GIVEN AS LIST WITH DICTIONARIES INSIDE

#READS THE DATA 
try:
    with open(storage, "rb") as f:


        #Checks if the database is empty
        if f.read() == b'':
            print("file empty")
            empty = True

        else:
            f.seek(0)

            salt = f.read(16)

            tag = f.read(16)

            nonce = f.read(16)

            ciphertext = f.read()

            empty = False


#Creates database if none exists

except FileNotFoundError:
    with open(storage, "wb") as f:
        empty = True
        pass



#DECRYPTS THE DATA 
if empty == False:

    try:
        message = decrypt(ciphertext, tag, nonce, password, salt)
    except ValueError:
        print("Retry, decryption failed ur cooked lilbro")
        sys.exit()




while True:

    choice = input("a. Add password  b. Print Passwords  c. Clear Database d. Exit \n")

    if choice == "a":

        website = input("Enter website: ")
        user = input("Enter username: ")
        loginpass = input("Enter password: ")
        

        confirmation = input(f"Website:{website} Username:{user} Password:{loginpass} Is this correct y/n \n")


        if confirmation == "y":

            #Puts all of the data into a dictionary
            login = {"Website": website, "Username": user, "Password": loginpass}

            if empty == False:
                #Adds the login to the list
                
                message.append(login)
                
                print("Login added")

            if empty == True:
                #Creates a list with the login dictionary in it
                message = [login]
                print("login added")



    elif choice == "b":
        try:
            for i in message:
                print(i.values())
        except NameError:
            print("File's empty")


    elif choice == "c":
        if input("Are you sure you want to clear EVERYTHING? y/n \n") == "y":
            with open("storage.bin", "wb") as f:
                pass
            sys.exit()


    elif choice == "d":
        #Generate new key and nonce, salt, and tag
      
        
        key, salt = getKey(password)
        #Rencryption of data
        ciphertext, tag, nonce = encrypt(key, message)

        #Writing everything back to the file
        with open("storage.bin", "wb") as f:
            f.write(salt)
            f.write(tag)
            f.write(nonce)
            f.write(ciphertext)
        print("Data encrypted and Stored")
        sys.exit()


    else:
        print("Enter valid option bozo")
        continue







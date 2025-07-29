import atexit
import argon2
#https://argon2-cffi.readthedocs.io/en/stable/api.html

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
import json
#I'll add a GUI if i feel like it lol

#haha guys im aura farming by making insecure password manager


password = input("Enter Password: ")


#HM OK CHAT ACTUALLY IT GIVES THE BASE64 AND NOT ACTUAL BYTES SO CHAT WAIT A SEC
#This generates the 32 byte key from the password using argon2
def getKey(password=None, salt=None):

    #Prompts for a password if one isn't given
    if password == None:
        password = input("Enter Password: ")

    #Turns the string to bytes
    password = password.encode()


    #Generate random 16 byte salt
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


def decrypt(ciphertext, tag, nonce, key):

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)

    message = message.decode()
    message = json.loads(message)

    return message

    
    




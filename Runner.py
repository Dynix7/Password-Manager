import atexit
import argon2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
#I'll add a GUI if i feel like it lol

#haha guys im aura farming by making insecure password manager

#Generate salt, Added to the password so hash output is differnt and rainbow table less work
salt = b''

#Sets up the argon2 thingy
ph = argon2.PasswordHasher()

password = input("Enter Password: ")




def getKey(password=None):

    #Prompts for a password if one isn't given
    if password == None:
        password = input("Enter Password: ")
    #Generates the Hash from given password and gives the Salt and the Hash
    result = ph.hash(password)

    parts = result.split("$")

    #Separates the given and only returns the salt and hash not the other parameters
    #btw i can only give the salt and key this only works since im just using the default settings for this

    salt = parts[4]
    key = parts[5]

    return key, salt


print(getKey(password=password))




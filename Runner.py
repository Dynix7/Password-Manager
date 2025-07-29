import atexit
import argon2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
#I'll add a GUI if i feel like it lol

#haha guys im aura farming by making insecure password manager

#Generate salt, Added to the password so hash output is differnt and rainbow table less work
salt = b''


password = input("Enter Password: ")

ph = argon2.PasswordHasher()







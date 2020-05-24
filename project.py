# -*- coding: utf-8 -*-
"""
Created on Mon May 11 16:34:52 2020

@author: rabia
"""

#%%
from helperclass import *
import tkinter as tk
from tkinter import *
from tkinter import ttk
import os
import sys
import os.path
from tkinter import messagebox
from os import listdir
from os.path import isfile, join
from functools import partial
from Crypto.PublicKey import RSA


key = b'p2r5u8x/A?D(G+KbPeShVmYq3t6v9y$B'
keydes = b'mYq3t6w9z$C&F)J@'
enc = AESEncr(key)
desenc = ThreeDES()
hashenc = Hash()
keypair = RSA.generate(3072)      
pubKey = keypair.publickey()
privKeyPEM = keypair.exportKey()  
rsa = RSAENC(keypair,pubKey,privKeyPEM)
clear = lambda: os.system('cls')
loggedInf = ''
registerInf = ''

def restart_program():
    """Restarts the current program.
    Note: this function does not return. Any cleanup action (like
    saving data) must be done before calling this function."""
    python = sys.executable
    os.execl(python, python, * sys.argv)

def clearFrame():
    # destroy all widgets from frame
    for widget in window.winfo_children():
       widget.destroy()

def clearEntry(filename):
    filename.delete(first=0,last=100) 
    
def validateLogin(username,password):
    enc.decryptFile('data.txt.enc')
    p=''
    with open("data.txt", "r") as f:
        p = f.read()
    str1 = p.split(' ', 1)
    if (str1[0] == username.get()) and (str1[1] == password.get()):
        enc.encryptFile("data.txt")
        loggedInf = 'Logged In'
    if (str1[0] != username.get()) and (str1[1] == password.get()):
        enc.encryptFile("data.txt")
        messagebox.showinfo("Title", "Username is incorrect.")
    if (str1[0] == username.get()) and (str1[1] != password.get()):
        enc.encryptFile("data.txt")
        messagebox.showinfo("Title", "Password is incorrect.")
    if (str1[0] != username.get()) and (str1[1] != password.get()):
        enc.encryptFile("data.txt")
        messagebox.showinfo("Title", "Username or password is incorrect.")
    elif loggedInf == 'Logged In':
        clearFrame()
        mainPage()
    print(loggedInf)
    
def register(username,password,passwordC):
    if password.get() == passwordC.get():
        f = open("data.txt", "w+")
        lines = [username.get()," "+password.get()]
        f.writelines(lines)
        f.close()
        enc.encryptFile("data.txt")
        registerInf = 'Registered'
        messagebox.showinfo("Title", "Registration done. Please restart the program.")
        restart_program()
    else:
        messagebox.showinfo("Title", "Passwords does not match.")
    print(registerInf)
    
def encryptwithAES(filename):
    enc.encryptFile(filename.get())
    messagebox.showinfo("Title", "Encryption with AES is done.")
    

def decryptwithAES(filename):
    enc.decryptFile(filename.get())
    messagebox.showinfo("Title", "Decryption with AES is done.")
    
def encryptwithDES3(filename):
    desenc.ThreeDESEncryptFile(filename.get())
    messagebox.showinfo("Title", "Encryption with 3DES is done.")

def decryptwithDES3(filename):
    desenc.ThreeDESDecryptFile(filename.get())
    messagebox.showinfo("Title", "Decryption with 3DES is done.")
    
def encryptwithRSA(filename):
    rsa.RSAFileEncrypt(filename.get())
    messagebox.showinfo("Title", "Encryption with RSA is done.")

def decryptwithRSA(filename):
    rsa.RSAFileDecrypt(filename.get())
    messagebox.showinfo("Title", "Decryption with RSA is done.")
   
def close():
    window.destroy()

window = Tk()
window.geometry('750x300+300+300')
window.title("Security Encryption App")

def loginPage():
    #username label and text entry box
    Label(window, text="Please enter login details").pack()
    usernameLabel = Label(window, text="User Name", width="30").pack()
    username = StringVar()
    usernameEntry = Entry(window, textvariable=username,width="30").pack()
    
    #password label and password entry box
    passwordLabel = Label(window,text="Password").pack() 
    password = StringVar()
    passwordEntry = Entry(window, textvariable=password, show='*',width="30").pack()
    validate = partial(validateLogin, username, password)
    Label(window, text="").pack()
    loginButton = Button(window, text="Login",width="25",command=validate).pack() 

def registerPage():
    Label(window, text="Please register the system").pack()
    usernameLabel = Label(window, text="User Name").pack()
    username = StringVar()
    usernameEntry = Entry(window, textvariable=username, width="30").pack()
    
    #password label and password entry box
    passwordLabel = Label(window,text="Password").pack() 
    password = StringVar()
    passwordEntry = Entry(window, textvariable=password, show='*', width="30").pack()
    passwordLabel = Label(window,text="Confirm Password").pack() 
    passwordC = StringVar()
    passwordEntry = Entry(window, textvariable=passwordC, show='*', width="30").pack()
    registerPage = partial(register,username,password,passwordC)
    
    
    Label(window, text="").pack()
    loginButton = Button(window, text="Register", width="25", command=registerPage).pack()
    
def mainPage():
    Label(window, text="Encryption/Decryption Page").pack()
    Label(window, text=" ").pack()
    Label(window, text="Before encrypting a file you may take backup in another file. After encryption your file will be gone.").pack()
    filenameLabel = Label(window, text="Enter name of the file with extension. If you want to decrypt a file please do not forget '.enc' part of it. ").pack()
    filename = StringVar()
    fileNameEntry = Entry(window, textvariable=filename).pack()
    Label(window, text="").pack()
    enc1 = partial(encryptwithAES, filename)
    enc1b = Button(window, text="Encrypt with AES", command=enc1).pack(in_=window, side=LEFT,padx=10, pady=5)
    dec1 = partial(decryptwithAES, filename)
    dec1b = Button(window, text="Decrypt with AES", command=dec1).pack(in_=window, side=LEFT,padx=5, pady=5)
    enc2 = partial(encryptwithDES3, filename)
    enc2b = Button(window, text="Encrypt with 3DES", command=enc2).pack(in_=window, side=LEFT,padx=5, pady=5)
    dec2 = partial(decryptwithDES3, filename)
    dec2b = Button(window, text="Decrypt with 3DES", command=dec2).pack(in_=window, side=LEFT,padx=5, pady=5)
    enc3 = partial(encryptwithRSA, filename)
    enc3b = Button(window, text="Encrypt with RSA", command=enc2).pack(in_=window, side=LEFT,padx=5, pady=5)
    dec3 = partial(decryptwithRSA, filename)
    dec3b = Button(window, text="Decrypt with RSA", command=dec2).pack(in_=window, side=LEFT,padx=5, pady=5)
    ex = partial(close)
    exb = Button(window, text="Exit", command=ex).pack(in_=window, side=LEFT,padx=5, pady=5)

if(os.path.isfile('data.txt.enc')):
    loginPage()
   
    

else:
    clear()
    registerPage()
    #window.destroy()
window.mainloop()
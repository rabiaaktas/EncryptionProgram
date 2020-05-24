# -*- coding: utf-8 -*-
"""
Created on Wed May  6 02:12:07 2020

@author: rabia
"""

# -*- coding: utf-8 -*-
"""
Created on Sun Apr 26 15:43:05 2020

@author: rabia
"""
#%%
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time
import hashlib
##key = ''.join(chr(random.randint(0, 100)) for i in range(16))
##iv = ''.join([chr(random.randint(0, 100)) for i in range(16)])
##im = plt.imread('ex.jpg')
##plt.imshow(im)
##np.savetxt("im.txt", (im.shape[0],im.shape[1]), fmt="%s")

key = b'p2r5u8x/A?D(G+KbPeShVmYq3t6v9y$B'
keydes = b'mYq3t6w9z$C&F)J@'

class AESEncr:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        return iv + encryptor.encrypt(message)

    def encryptFile(self, fileName):
        with open(fileName, 'rb') as f:
            plaintext = f.read()
        enc = self.encrypt(plaintext, self.key)
        with open(fileName + ".enc", 'wb') as f:
            f.write(enc)
        os.remove(fileName)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        plaintext = decryptor.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decryptFile(self, fileName):
        with open(fileName, 'rb') as f:
            ciphertext = f.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(fileName[:-4], 'wb') as f:
            f.write(dec)
        os.remove(fileName)
class ThreeDES():
    def __init__(self):
        self.self=self
        
    def pad(self, s):
        return s + b"\0" * (DES3.block_size - len(s) % DES3.block_size)
    
    def ThreeDESEncrypt(self, message, key, key_size=192):
        message = self.pad(message)
        iv = Random.new().read(DES3.block_size)
        encryptor = DES3.new(key, DES3.MODE_CBC, iv)
        return iv + encryptor.encrypt(message)
        
    def ThreeDESEncryptFile(self, fileName):
        with open(fileName,'rb') as f:
            plaintext = f.read()
        enc = self.ThreeDESEncrypt(plaintext, keydes)
        with open(fileName+".enc",'wb') as f:
            f.write(enc)
        os.remove(fileName)
    
    def ThreeDESDecrypt(self,ciphertext, key):
        iv = ciphertext[:DES3.block_size]
        decryptor = DES3.new(keydes, DES3.MODE_CBC, iv)
        plaintext = decryptor.decrypt(ciphertext[DES3.block_size:])
        return plaintext.rstrip(b"\0")
    
    def ThreeDESDecryptFile(self, fileName):
        with open(fileName,'rb') as f:
            ciphertext = f.read()
        dec = self.ThreeDESDecrypt(ciphertext, keydes)
        with open(fileName[:-4],'wb') as f:
            f.write(dec)
        os.remove(fileName)
        
class RSAENC():
    def __init__(self,keypair,publicKey,privateKey):
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.keypair = keypair
        
    def RSAEncrypt(self,message):
        encryptor = PKCS1_OAEP.new(self.publicKey)
        encrypted = encryptor.encrypt(message)
        return encrypted
    
    def RSAFileEncrypt(self,fileName):
        with open(fileName,'rb') as f:
            plaintext = f.read()
        enc = self.AESEncrypt(plaintext)
        with open(fileName+".enc",'wb') as f :
            f.write(enc)
        os.remove(fileName)
    
    def RSADecrypt(self,message):
        decryptor = PKCS1_OAEP.new(self.keypair)
        decrypted = decryptor.decrypt(message)
        return decrypted
    
    def RSAFileDecrypt(self,fileName):
        with open(fileName,'rb') as f:
            ciphertext = f.read()
        dec = self.AESDecrypt(ciphertext)
        with open(fileName[:-4],'wb') as f:
            f.write(dec)
        os.remove(fileName)
       
class Hash():
    def __init__(self):
        self.self = self
        
    def sha512enc(self,plaintext):
        res = hashlib.sha512(plaintext)
        return res.hexdigest()
    
    def sha512fileEncr(self,fileName):
        with open(fileName,'rb') as f:
            plaintext = f.read()
        dec = self.sha512enc(plaintext)
        with open(fileName+".enc",'w') as f:
            f.write(dec)
        os.remove(fileName)

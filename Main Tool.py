from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox #needed for popup messages
import rsa #library needed for RSA encryption
import hashlib #module needed for hashing algorthms
from PIL import ImageTk,Image
from tkinter import filedialog #used to interract with files on the users computer (mainly used for importing files to text boxes)
from random import randint #needed to generate random characters for password generation module
from Crypto.Random import get_random_bytes #The get_random_bytes function in this module generates a specified number of random bytes, which can be used as a salt for a key in cryptographic operations.
from Crypto.Protocol.KDF import PBKDF2 #PBKDF2 used for extra layer of security, using password based encryption within AES
from Crypto.Cipher import AES #main library were using for symmetric encryption and decryption
from Crypto.Util.Padding import pad, unpad
import requests #module needed to pull text from urls in username generation module
import random
import sqlite3 #used as the Database management system
import bcrypt # this library is used for hashing/salting credentials into the database as a security measure
import time #used to measure time for when do delete the splash screen window


#------------------------------------------------------------------------------encryption algorithms----------------------------------------------------------
def encrypt_text():
    text_content = myText.get(1.0, "end-1c")
    text_content_encoded = text_content.encode('utf-8') # Encryption and hashing algorithms typically work on binary data, not text. therefore we encode the messages in the text box before running through algorithms)
    if myCombo.get() == 'RSA-2048':
        if len(text_content.encode('utf-8')) <= 117:  # checking how long the message is since rsa has its limitations for number of characters 
            response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
            # Encrypt the message with the public key and store it in a text file
            if response == 'yes':
                encrypted_message = rsa.encrypt(text_content_encoded, public_key2048)
                with open('encrypted_message.txt', 'wb') as f:
                    f.write(encrypted_message)
                success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the 'encrypted_message.txt' file")
            elif response == 'no':
                #encrypt text with public key and insert into text box
                encrypted_message = rsa.encrypt(text_content_encoded, public_key2048)
                with open('encrypted_message.txt', 'wb') as f: 
                    f.write(encrypted_message) # storing the encrypted msg in file anyway, since it may be helpful to be found here for decryption, havent done this for AES anlgorithms so if RSA decryption works and AES dosent this may be why
                myText.delete(1.0, "end")
                myText.insert(1.0, encrypted_message)
                success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the text box")
        else:
            response = messagebox.showerror("Error", "Text is too long to encrypt with RSA.")
            
    elif myCombo.get() == 'RSA-1024': 
        if len(text_content.encode('utf-8')) <= 117:  # Encoding the message to bytes/binary, must be done before encryption
            response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
            # Encrypt the message with the public key and store it in a text file
            if response == 'yes':
                encrypted_message = rsa.encrypt(text_content_encoded, public_key1024)
                with open('encrypted_message.txt', 'wb') as f:
                    f.write(encrypted_message)
                success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the 'encrypted_message.txt' file")
            elif response == 'no':
                encrypted_message = rsa.encrypt(text_content_encoded, public_key1024)
                with open('encrypted_message.txt', 'wb') as f: 
                    f.write(encrypted_message) # storing the encrypted msg in file anyway, since it may be helpful to be found here for decryption
                myText.delete(1.0, "end")
                myText.insert(1.0, encrypted_message)
                success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the text box")
        else:
            response = messagebox.showerror("Error", "Text is too long to encrypt with RSA.")
            return
        
    elif myCombo.get() == 'AES-192':
            response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
            with open ('aes_192_key.bin','rb') as f:
                aes_192_key = f.read()
            if response == 'yes':
                    msg = myText.get(1.0, "end").encode('utf-8')  #encoding the content which the user has inputed since this needs to be done before encryption
                   
                    # Create a new AES cipher object with the provided 192-bit key (aes_192_key) and using CBC mode.
                    #CBC (Cipher Block Chaining) is a block cipher mode that uses the previous ciphertext block as an IV for the next block.
                    
                    cipher = AES.new(aes_192_key, AES.MODE_CBC)
                    Cipheredtext = cipher.encrypt(pad(msg, AES.block_size)) # Pad the message (msg) to a multiple of the AES block size using PKCS7 padding.This ensures that the message length is a multiple of the block size before encryption.
                    with open('encrypted_message.txt','wb') as f:
                        f.write(cipher.iv) #Writing the Initialization Vector (IV) used by the AES cipher to the file.The IV is needed for decryption and should be kept secret.
                        f.write(Cipheredtext) #writitng the ciphered result to the encrypted message file
                    success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the 'encrypted_message.txt' file")
            elif response == 'no':
                    msg = myText.get(1.0, "end").encode('utf-8')
                    cipher = AES.new(aes_192_key, AES.MODE_CBC)
                    Cipheredtext = cipher.encrypt(pad(msg, AES.block_size))
                    myText.delete(1.0, "end")
                    myText.insert(1.0, Cipheredtext)
                    success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the text box")
    elif myCombo.get() == 'AES-128':
            response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
            with open ('aes_128_key.bin','rb') as f:
                aes_128_key = f.read()
            if response == 'yes':
                    msg = myText.get(1.0, "end").encode('utf-8')
                    cipher = AES.new(aes_128_key, AES.MODE_CBC)
                    Cipheredtext = cipher.encrypt(pad(msg, AES.block_size))
                    with open('encrypted_message.txt','wb') as f:
                        f.write(cipher.iv)
                        f.write(Cipheredtext)
                    success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the 'encrypted_message.txt' file")
            elif response == 'no':
                    msg = myText.get(1.0, "end").encode('utf-8')
                    cipher = AES.new(aes_128_key, AES.MODE_CBC)
                    Cipheredtext = cipher.encrypt(pad(msg, AES.block_size)) 
                    myText.delete(1.0, "end")
                    myText.insert(1.0, Cipheredtext)
                    success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the text box")
    elif myCombo.get() == 'AES-256':
        response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
        with open ('aes_256_key.bin','rb') as f:
            aes_256_key = f.read()
        if response == 'yes':
            msg = myText.get(1.0, "end").encode('utf-8')
            cipher = AES.new(aes_256_key, AES.MODE_CBC)
            Cipheredtext = cipher.encrypt(pad(msg, AES.block_size))
            with open('encrypted_message.txt','wb') as f: #changed the file from encrypted_bin to encrypted_message.txt fo the sake of consistency when storing encrypted data. if theres problems mabye refer back to filetype.
                f.write(cipher.iv)
                f.write(Cipheredtext)
            success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the 'encrypted_message.txt' file")
        elif response == 'no':
            msg = myText.get(1.0, "end").encode('utf-8')
            cipher = AES.new(aes_256_key, AES.MODE_CBC)
            Cipheredtext = cipher.encrypt(pad(msg, AES.block_size))
            myText.delete(1.0, "end")
            myText.insert(1.0, Cipheredtext)
            success_msg = messagebox.showinfo("Successful", "Your encrypted message can be found in the text box")

#------------------------------------------------------------------------------decryption algorithms----------------------------------------------------------

def decrypt_text():    
    if myCombo_decrypt.get() == 'RSA-2048':
        with open('private.pem', 'rb') as f:       #opening the rsa2048 keyfile and storing in variable
            private_key2048 = rsa.PrivateKey.load_pkcs1(f.read())

        encrypted_msg = myText_Decrypt.get("1.0", "end-1c").encode('utf-8')    #stroring text boxs' encrypted contents into variable

        try:
            clear_msg = rsa.decrypt(encrypted_msg, private_key2048)   #decrypts encrypted message and stores in variable
            clear_msg = clear_msg.decode('utf-8')

            myText_Decrypt.delete(1.0, 'end')
            myText_Decrypt.insert(1.0, clear_msg)
        except rsa.DecryptionError:                                 #error validation indicating when decryption isn't successful
            messagebox.showerror("Error", "Decryption failed. Make sure the correct private key is loaded.")

    elif myCombo_decrypt.get() == 'RSA-1024':
        with open('private_1024.pem','rb') as f:
            private_key1024 = rsa.PrivateKey.load_pkcs1(f.read())

        encrypted_msg = myText_Decrypt.get("1.0", "end-1c").encode('utf-8')   # would work if you decrypt the contents of encrypted_message.txt file: encrypted_msg = open('encrypted_message.txt','rb').read()
        try:
            clear_msg = rsa.decrypt(encrypted_msg, private_key1024)
            clear_msg = clear_msg.decode('utf-8')
       
            myText_Decrypt.delete(1.0,'end')
            myText_Decrypt.insert(1.0,clear_msg)
        except rsa.DecryptionError:
           messagebox.showerror("Error", "Decryption failed. Make sure the correct private key is loaded.")

    
    elif myCombo_decrypt.get() == 'AES-128':
        data =  myText_Decrypt.get(1.0,END)                #storing content to decrypt in variable
        with open('encrypted_message.txt','wb') as f:   
          f.write(data)            #writing data which is already encrypted into file to minipulate there
        iv = f.read(16)            #creating IV from reading file and storing
        decrypt_data =  f.read()  
        f.close()                 
        with open('aes_128_key.bin','rb') as f:           #opening keyfile and storing key in variable
          key = f.read()
          f.close()
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)   
        original = unpad(cipher.decrypt(decrypt_data), AES.block_size)
        #initializes AES cipher for decryption using key and IV in (CBC) mode.

        response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
        if response == 'yes':
            myText_Decrypt.insert(1.0,original)  #inserting cleartext msg into text box
            success_msg = messagebox.showinfo("Successful!","Your decrypted message can be found in the text box")
        elif response == 'no':
            with open ('decrypted_message.txt','wb') as f: 
                f.write(original) #Storing cleartext message in txt file
            success_msg = messagebox.showinfo("Successful!","Your decrypted message can be found in the 'decrypted message' txt file")
                

    elif myCombo_decrypt.get() == 'AES-192':
        data =  myText_Decrypt.get(1.0,END)
        with open('encrypted_message.txt','wb') as f:
          f.write(data)
        iv = f.read(16)
        decrypt_data =  f.read()
        with open('aes_192_key.bin','rb') as f:
          key = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        original = unpad(cipher.decrypt(decrypt_data), AES.block_size)

        response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
        if response == 'yes':
            myText_Decrypt.insert(1.0,original)
            success_msg = messagebox.showinfo("Successful!","Your decrypted message can be found in the text box")
        elif response == 'no':
            with open ('decrypted_message.txt','wb') as f:
                f.write(original)
            success_msg = messagebox.showinfo("Successful!","Your decrypted message can be found in the 'decrypted message' txt file")

    elif myCombo_decrypt.get() == 'AES-256':
        data =  myText_Decrypt.get(1.0,END)
        with open('encrypted_message.txt','wb') as f:
          f.write(data)
        iv = f.read(16)
        decrypt_data =  f.read()
        with open('aes_256_key.bin','rb') as f:
          key = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        original = unpad(cipher.decrypt(decrypt_data), AES.block_size)

        response = messagebox.askquestion("Options", "Press 'yes' to store encrypted message in a txt file OR press 'no' to only put it in the text box")
        if response == 'yes':
            myText_Decrypt.insert(1.0,original)
            success_msg = messagebox.showinfo("Successful!","Your decrypted message can be found in the text box")
        elif response == 'no':
            with open ('decrypted_message.txt','wb') as f:
                f.write(original)
            success_msg = messagebox.showinfo("Successful!","Your decrypted message can be found in the 'decrypted message' txt file")

#--------------------------------------------------------------hashing algorithms------------------------------------------------------------------------------

def Hash_function():
    text_content = text_box_one.get(1.0, "end-1c")
    text_content_encoded = text_content.encode('utf-8') # Encryption and hashing algorithms typically work on binary data, not text. therefore we encode the messages in the text box before running through algorithms)
    
    if myCombo_hash.get() == 'SHA-256':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('SHA256')
        text_content_bytes = text_content_encoded  
        h.update(text_content_bytes)
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    elif myCombo_hash.get() == 'SHA-3':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('sha3_256') #using SHA 3 function with a size of 256 bits.
        text_content_bytes = text_content_encoded 
        h.update(text_content_bytes) 
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    elif myCombo_hash.get() == 'MD5':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('MD5')
        text_content_bytes = text_content_encoded
        h.update(text_content_bytes)
        hashed_value = h.hexdigest()
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    elif myCombo_hash.get() == 'SHA-512':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('sha512')
        text_content_bytes = text_content_encoded
        h.update(text_content_bytes)
        hashed_value = h.hexdigest()
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    elif myCombo_hash.get() == 'SHA-224':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('sha224')
        text_content_bytes = text_content_encoded
        h.update(text_content_bytes)
        hashed_value = h.hexdigest()
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    elif myCombo_hash.get() == 'blake2s':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('blake2s')
        text_content_bytes = text_content_encoded
        h.update(text_content_bytes)
        hashed_value = h.hexdigest()
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    elif myCombo_hash.get() == 'blake2b':
        text_box_two.delete(1.0,'end')
        h = hashlib.new('blake2b')
        text_content_bytes = text_content_encoded
        h.update(text_content_bytes)
        hashed_value = h.hexdigest()
        result = (h.hexdigest())
        text_box_two.insert(1.0,result)
    else:
        messagebox.showerror("Error", "Please select a Hashing algorithm")
#------------------------------------------------------------------AES 128,192,256 key generation-----------------------------------------------------------------------

def generate_key_aes128():
        global aes_128_key,key_reset
        salt = b'j\x8dn\xa9\x17\x00\xf2\x85?\t\xff9\x89\xc5\xb9w/\x05(\xe1\xc1u$\x82' #16 byte salt for the key generation
        passw = 'mypassword'
        aes_128_key = PBKDF2(passw, salt, dkLen=16)
        with open('aes_128_key.bin','wb') as f:
            f.write(aes_128_key)
        if key_reset == True:
            simple_key = get_random_bytes(16) #creating a brand new 16 byte salt for a new key and storing in variable below
            salt = simple_key 
            PBKDF2_Generate_pw()
            passw = password
            aes_128_key = PBKDF2(passw, salt, dkLen=16)
            with open('aes_128_key.bin','wb') as f:
               f.write(aes_128_key)
               f.close()
            with open('aes_128_key.bin','rb') as f:
               the_key = f.read()
            key_reset = False
            messagebox.showinfo('Success','you have successfully reset your AES key which can be found in the text box')
            clear_aeskey_box()
            AES_key_box.insert(1.0,the_key)
    
def generate_key_aes192():
        global aes_192_key,key_reset
        salt =b'\xfe\xca\xeeL\x15\xb9=\x95\x93v\xdeg\x97\x88F\x0b\x86\xe1>\xf16\x7fY\x95' #24 byte salt for the key generation
        passw = 'mypassword' #default password for the PBKDF2 based encryption
        aes_192_key = PBKDF2(passw, salt, dkLen=24)
        with open('aes_192_key.bin','wb') as f:
            f.write(aes_192_key)
        if key_reset == True:
            simple_key = get_random_bytes(24) #creating a brand new 24 byte salt for a new key 
            salt = simple_key #setting the new salt for the new key
            PBKDF2_Generate_pw()    #function to create a new password for the key to pass into PBKDF2 for the password based encryption, this plays a part in changing the key, as well as the salf
            passw = password  #putting the password which has been generated from the above function into the passw variable for the new key
            aes_192_key = PBKDF2(passw, salt, dkLen=24) #new key made
            with open('aes_192_key.bin','wb') as f:
               f.write(aes_192_key) #writing new key to binary file
               f.close()
            with open('aes_192_key.bin','rb') as f:
               the_key = f.read()
            key_reset = False #setting the variable to false so that the key dosent get generated again when this function is called again. Unless another function calls it and sets it back to true
            messagebox.showinfo('Success','you have successfully reset your AES key which can be found in the text box')
            clear_aeskey_box()
            AES_key_box.insert(1.0,the_key) #inserting key into text box which has been read from file after being newly generated (this is used in yhr )

def generate_key_aes256():
        global aes_256_key,key_reset
        salt = b'\xc9E\xd5\xef|\xba\xd3<\x11N\xbeG\x85o\x80\xc2\x92%\xdc{p\xe9\xa2\xefuS\xbeZ\xe9\xd7^\xe2' #32 byte salt for the key generation
        passw = 'mypassword'
        aes_256_key = PBKDF2(passw, salt, dkLen=32)
        with open('aes_256_key.bin','wb') as f:
            f.write(aes_256_key)
            f.close()
        if key_reset == True:
            simple_key = get_random_bytes(32) #creating a brand new 32 byte salt for a new key 
            salt = simple_key
            PBKDF2_Generate_pw()
            passw = password
            aes_256_key = PBKDF2(passw, salt, dkLen=32)
            with open('aes_256_key.bin','wb') as f:
               f.write(aes_256_key)
            with open('aes_256_key.bin','rb') as f:
               the_key = f.read()
            key_reset = False
            messagebox.showinfo('Success','you have successfully reset your AES key which can be found in the text box')
            clear_aeskey_box()
            AES_key_box.insert(1.0,the_key)
#------------------------------------------------------------------RSA 2048 key generation---------------------------------------------------------
def generate_keys_rsa2048():
 if myCombo.get() == 'RSA-2048':
        public_key2048, private_key2048 = rsa.newkeys(2048)
    # Save the keys to files
        with open('public.pem', 'wb') as f:
            f.write(public_key2048.save_pkcs1('PEM'))
        with open('private.pem', 'wb') as f:
            f.write(private_key2048.save_pkcs1('PEM'))

def load_keys_rsa2048():
    # Load keys from files
    try:
        with open('public.pem', 'rb') as f:
            public_key2048 = rsa.PublicKey.load_pkcs1(f.read())
        with open('private.pem', 'rb') as f:
            private_key2048 = rsa.PrivateKey.load_pkcs1(f.read())
    except FileNotFoundError:
        # If the keys don't exist, generate new ones
        generate_keys_rsa2048()
    else:
        return public_key2048, private_key2048

# were calling the load_keys_rsa2048 function to get keys from files and assign them to the public/private key which we will use 
public_key2048, private_key2048 = load_keys_rsa2048()

#-------------------------------------------------------------------------RSA 1024 key Generation---------------------------------------------------
def generate_keys_rsa1024():
 if myCombo.get() == 'RSA-1024':
        public_key1024, private_key1024 = rsa.newkeys(1024)
    # Save the keys to files
        with open('public_rsa_1024.pem', 'wb') as f:
            f.write(public_key1024.save_pkcs1('PEM'))
        with open('private_rsa_1024.pem', 'wb') as f:
            f.write(private_key1024.save_pkcs1('PEM'))
        
def load_keys_rsa1024():
    # Load keys from files
    try:
        with open('public_rsa_1024.pem', 'rb') as f:
            public_key1024 = rsa.PublicKey.load_pkcs1_openssl_pem(f.read())
        with open('private_rsa_1024.pem', 'rb') as f:
            private_key1024 = rsa.PrivateKey.load_pkcs1(f.read())
    except FileNotFoundError:
        # If the keys don't exist, generate new ones
        generate_keys_rsa1024()
    else:
        return public_key1024, private_key1024

# were calling the load_keys_rsa2048 function to get keys from files and assign them to the public/private key which we will use 
public_key1024, private_key1024 = load_keys_rsa1024()


#----------------------------------------------------------Key reset functions --------------------------------------------------

def auto_generate_rsakey():  
    if myCombo_key.get() == 'RSA-1024':
            response = messagebox.askquestion("Options", "Are you sure you'd like to continue/reset your key?\n Current RSA key pair will be permanently overwritten")
            if response == 'yes':  
                public_key1024, private_key1024 = rsa.newkeys(1024) #making new rsa 1024 key pair
                with open('public_rsa_1024.pem', 'wb') as f:  #saving new pair to files
                    f.write(public_key1024.save_pkcs1('PEM'))
                with open('private_rsa_1024.pem', 'wb') as f:
                    f.write(private_key1024.save_pkcs1('PEM'))
                success_msg = messagebox.showinfo("Successful", "You've generated a new RSA-2048 key pair\n new key pair can be found in the text boxes")
                clear_rsabox() #clearning the current contents of the text box before inserting new key
                f = open('private_rsa_1024.pem','r')
                newpriv_key = f.read()  
                First_box.insert(1.0,newpriv_key)
                f.close()
                f= open('public_rsa_1024.pem','r')
                newpub_key = f.read()
                second_box.insert(1.0,newpub_key)
                f.close()
            elif response == 'no':
                return
        
    elif myCombo_key.get() == 'RSA-2048':
        response = messagebox.askquestion("Options", "Are you sure you'd like to continue/reset your key?\n Current RSA key pair will be permanently overwritten")
        if response == 'yes':  
                public_key2048, private_key2048 = rsa.newkeys(2048)
                with open('public.pem', 'wb') as f:
                    f.write(public_key2048.save_pkcs1('PEM'))
                with open('private.pem', 'wb') as f:
                    f.write(private_key2048.save_pkcs1('PEM'))
                    f.close()
                success_msg = messagebox.showinfo("Successful", "You've generated a new RSA-2048 key pair\n new key pair can be found in the text boxes")
                clear_rsabox() #clearing the current contents of the text box before inserting new key
                f = open('private.pem','r')
                newpriv_key = f.read()
                First_box.insert(1.0,newpriv_key)
                f.close()
                f= open('public.pem','r')
                newpub_key = f.read()
                second_box.insert(1.0,newpub_key)
                f.close()
        elif response == 'no':
            return
        
def auto_generate_aeskey():  
    global key_reset
    response = messagebox.askquestion("Options", "Are you sure you'd like to continue/reset your key?\n Current RSA key pair will be permanently overwritten")
    if response == 'yes':
        if myCombo_aes_key.get() == 'AES-128':
            key_reset = True   #setting this variable to TRUE bool, the part of the generate_key_x function which is used to make a new key is run
            generate_key_aes128() #function to generate new key
        elif myCombo_aes_key.get() == 'AES-192':
            key_reset = True 
            generate_key_aes192()
        elif myCombo_aes_key.get() == 'AES-256':
            key_reset = True 
            generate_key_aes256()
    else: return
    
def manually_setRSA_key(myCombo_key):
    if myCombo_key.get() == 'RSA-1024':  #if the currently seleceted choice in the dropbox is RSA1024 this function will run
        response = messagebox.askquestion("Options", "Are you sure you'd like to continue/reset your key?\n Current RSA key pair will be permanently overwritten")
        if response == 'yes':
            user_priv_key = First_box.get(1.0,'end')
            user_pub_key = second_box.get(1.0,'end')
            with open ('private_rsa_1024.pem','wb') as f:
                f.write(user_priv_key.encode())  # this function expects a bytes like object so the string needs to be encoded to bytes before writing it to the file otherwise there will be errors
            with open ('public_rsa_1024.pem','wb') as f:
                f.write(user_pub_key.encode())
            success_msg = messagebox.showinfo("Successful", "You've Reset your RSA key pair\n to your custom shoice")
        else:
            return

    elif myCombo_key.get() == 'RSA-2048': #this function will run in the event that the RSA2048 key is chosen to manually reset
        response = messagebox.askquestion("Options", "Are you sure you'd like to continue/reset your key?\n Current RSA key pair will be permanently overwritten")
        if response == 'yes':
            user_priv_key = First_box.get(1.0,'end')
            user_pub_key = second_box.get(1.0,'end')
            with open ('private.pem','wb') as f:
                f.write(user_priv_key.encode())
            with open ('public.pem','wb') as f:
                f.write(user_pub_key.encode())
            success_msg = messagebox.showinfo("Successful", "You've Reset your RSA key pair\n to your custom shoice")
        else:
            return

#----------------------------------------------------------------------------Functions for viewing current keys------------------------------------------------------------
def view_key():
    if myCombo_key.get()   == 'RSA-1024 (private)':
        clear_keyview_box() #emptying the contents of the box before putting the key in
        f = open('private_rsa_1024.pem','r') #opening file in reading format
        the_key = f.read() #storing the contents of the priivate rsa file which is the private key into variable
        key_text_box.insert(1.0, the_key)  #inserting the content of this variable into the text box 
        success_msg = messagebox.showinfo("success","Your current key can be found in the text box")   #success message to confirm the correct key being shown
    elif myCombo_key.get() == 'RSA-1024 (public)':
        clear_keyview_box()
        f = open('public_rsa_1024.pem','r')
        the_key = f.read()
        key_text_box.insert(1.0, the_key)
        success_msg = messagebox.showinfo("success","Your current key can be found in the text box")
    elif myCombo_key.get() == 'RSA-2048 (private)':
        clear_keyview_box()
        f = open('private.pem','r')
        the_key = f.read()
        key_text_box.insert(1.0, the_key)
        success_msg = messagebox.showinfo("success","Your current key can be found in the text box")
    elif myCombo_key.get() == 'RSA-2048 (public)':
        clear_keyview_box()
        f = open('public.pem','r')
        the_key = f.read()
        key_text_box.insert(1.0, the_key)
        success_msg = messagebox.showinfo("success","Your current key can be found in the text box")
    elif myCombo_key.get() == 'AES-128':
        clear_keyview_box()
        with open ('aes_128_key.bin','rb') as f:
            the_key = f.read()
            key_text_box.insert(1.0, the_key)
            success_msg = messagebox.showinfo("success","Your current key can be found in the text box")
    elif myCombo_key.get() == 'AES-192':
        clear_keyview_box()
        with open ('aes_192_key.bin','rb') as f:
            the_key = f.read()
            key_text_box.insert(1.0, the_key)
            success_msg = messagebox.showinfo("success","Your current key can be found in the text box")
    elif myCombo_key.get() == 'AES-256':
        clear_keyview_box()
        with open ('aes_256_key.bin','rb') as f:
            the_key = f.read()
            key_text_box.insert(1.0, the_key)
            success_msg = messagebox.showinfo("success","Your current key can be found in the text box")
    else: 
        error_msg = messagebox.showerror("Error","Invalid input")

#--------------------------------------------------funtions to clear text boxes from different pages------------------------------------------------
def clear():
    if Hashing_box == True:
        text_box_one.delete(1.0,'end')
        text_box_two.delete(1.0,'end')
    elif Hashing_box ==False:
        myText.delete(1.0,'end')
    
def clear_rsabox():
    First_box.delete(1.0,'end')
    second_box.delete(1.0,'end')
def clear_keyview_box():
    key_text_box.delete(1.0,'end')
def clear_decryptbox():
    myText_Decrypt.delete(1.0,'end')
def clear_aeskey_box():
    AES_key_box.delete(1.0,'end')

#--------------------------------------------------------------------------------------------------------------------------------------
def clear_pages():
    for frame in main_frame.winfo_children():
            frame.destroy()

def opentxt_file(): #this function is for importing text files into text boxes
    global open_file_button
    if Hashing_box == True:
        root.filename = filedialog.askopenfilename(initialdir="/", title='Select a file', filetypes=(('text files', '.txt'), ('all files', '*.*')))
        if root.filename:  # Check if a file was selected
            with open(root.filename, 'r') as file:
                file_contents = file.read() #reading the file which has been chosen and storing it in variable
                text_box_one.delete(1.0, "end")  # Clear the existing content of text_box_two
                text_box_one.insert(1.0, file_contents)  # Insert the file contents into text_box_two
        my_Label = Label(root, text=root.filename)
        my_Label.pack()
    elif Hashing_box == False:
        root.filename = filedialog.askopenfilename(initialdir="/", title='Select a file', filetypes=(('text files', '.txt'), ('all files', '*.*')))
        if root.filename:  # Check if a file was selected
            with open(root.filename, 'r') as file:
                file_contents = file.read()
                myText.delete(1.0, "end")  # Clear the existing content of text_box_two
                myText.insert(1.0, file_contents)  # Insert the file contents into text_box_two
        my_Label = Label(root, text=root.filename)
        my_Label.pack()

#---------------------------------------------------Creating seperate functions for the different pages -----------------------------------------------------
def encryption_page():
    global myText,myCombo,Hashing_box
    clear_pages()
    encryption_frame = tk.Frame(main_frame)
    for row in range(12):
        empty_label = tk.Label(encryption_frame, text='', bg='#a9a9a9')
        empty_label.grid(row=row, column=0, columnspan=3)
#--------------------making combo box-------------------------------
    encryption_options = ['AES-128','AES-256','AES-192','RSA-2048','RSA-1024']

    myCombo = ttk.Combobox(encryption_frame, value= encryption_options, width=30)
    myCombo.current(0)
    myCombo.bind('<<ComboboxSelected>>')
    myCombo.delete(0,END)
    myCombo.insert(0,'select an encryption algorithm')
    myCombo.place(x= 115, y=20)
#---------------------------------------------------------------
    myText = tk.Text(encryption_frame, height=10, width=50, borderwidth=4)
    myText.grid(row=8, column=0) 

    copy_to_clipboard = Button(encryption_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = lambda: clip_encrypted_val())
    copy_to_clipboard.place(x = 300, y = 340)
    
    clear_button = Button(encryption_frame, text='Clear all',width=10,bg='#a9a9a9', command = clear)
    clear_button.place(x=160, y=370)
    Hashing_box = False

    encrypt_button = Button(encryption_frame, text='Encrypt', width=15,bg='#a9a9a9', command=lambda: encrypt_text())
    encrypt_button.place(x=140,y=60)

    open_file_button = Button(encryption_frame, text='Import txt file',width=15, command = opentxt_file)
    open_file_button.place(x=25,y=133)

    encryption_frame.pack()

def Decryption_page():
    global myText_Decrypt,myCombo_decrypt

    Decryption_frame = tk.Frame(main_frame)
    for row in range(12):
        empty_label = tk.Label(Decryption_frame, text='', bg='#a9a9a9')
        empty_label.grid(row=row, column=0, columnspan=3)
#--------------------making combo box-------------------------------
    encryption_options = ['AES-128','AES-256','AES-192','RSA-2048','RSA-1024']

    myCombo_decrypt = ttk.Combobox(Decryption_frame, value= encryption_options, width=30)
    myCombo_decrypt.current(0)
    myCombo_decrypt.bind('<<ComboboxSelected>>')
    myCombo_decrypt.delete(0,END)
    myCombo_decrypt.insert(0,'select algorithm')
    myCombo_decrypt.place(x= 115, y=20)
#---------------------------------------------------------------
    myText_Decrypt = tk.Text(Decryption_frame, height=10, width=50, borderwidth=4)
    myText_Decrypt.grid(row=8, column=0) 

    copy_to_clipboard = Button(Decryption_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = lambda: clip_decrypted_val())
    copy_to_clipboard.place(x = 300, y = 340)
    
    clear_button = Button(Decryption_frame, text='Clear all',width=10,bg='#a9a9a9', command = clear_decryptbox)
    clear_button.place(x=160, y=370)

    decrypt_button = Button(Decryption_frame, text='Decrypt', width=15,bg='#a9a9a9', command=lambda: decrypt_text())
    decrypt_button.place(x=140,y=60)

    open_file_button = Button(Decryption_frame, text='Import txt file',width=15, command = opentxt_file)
    open_file_button.place(x=25,y=133)

    Decryption_frame.pack()
def Hashing_page():
    global text_box_one,text_box_two,myCombo_hash,Hashing_box,Hashing_box
    clear_pages()
    Hashing_frame = tk.Frame(main_frame)

    for row in range(12):
        empty_label = tk.Label(Hashing_frame, text='', bg='#c0c0c0')
        empty_label.grid(row=row, column=0, columnspan=4)
#----------------------------------------------making combo box-----------------------------------------------------------------------
    Hashing_options = ['SHA-512','SHA-256','SHA-224','SHA-3','MD5','blake2s','blake2b']
    myCombo_hash = ttk.Combobox(Hashing_frame, value= Hashing_options)
    myCombo_hash.current(0)
    myCombo_hash.bind('<<ComboboxSelected>>')
    myCombo_hash.delete(0,END)
    myCombo_hash.insert(0,'select hash function')
    myCombo_hash.place(x= 140, y=20)
#-----------------------------------------------------------------------------------------------------------------------------------
    text_box_one = tk.Text(Hashing_frame, height=10, width=25, borderwidth=4)
    text_box_one.grid(row=8, column=0) 
    text_box_two = tk.Text(Hashing_frame, height=10, width=25, borderwidth=4)
    text_box_two.grid(row=8, column=5) 
    
    clear_button = Button(Hashing_frame, text='Clear all', bg='#a9a9a9',width=10, command = clear)
    clear_button.place(x=165, y=370)
    Hashing_box = True
    Hash_button = Button(Hashing_frame, text='Hash', width=12,bg='#a9a9a9', command=lambda: Hash_function())
    Hash_button.place(x=165,y=65)

    copy_to_clipboard = Button(Hashing_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = lambda: clip_hashed_val())
    copy_to_clipboard.place(x = 300, y = 340)

    open_file_button = Button(Hashing_frame, text='Import txt file',width=15, command = opentxt_file)
    open_file_button.place(x=25,y=133)

    Hashing_frame.pack()

def AES_reset_page():
    global myCombo_key,myCombo_aes_key,box,AES_key_box

    AES_frame = tk.Frame(main_frame)

    autoset_btn = Button(AES_frame, text = 'Auto reset \nnew key ', bg='#a9a9a9', activeforeground='#0097e8', command = auto_generate_aeskey)
    autoset_btn.place(x=165,y=390)

    key_options = ['AES-128','AES-256','AES-192']
    myCombo_aes_key = ttk.Combobox(AES_frame, value= key_options)
    myCombo_aes_key.current(0)
    myCombo_aes_key.bind('<<ComboboxSelected>>')
    myCombo_aes_key.delete(0,END)
    myCombo_aes_key.insert(0,'select key')
    myCombo_aes_key.place(x= 140, y=40)

    AES_key_box = tk.Text(AES_frame, height=15, width=50, borderwidth=2)
    AES_key_box.place(x=5, y=110)

    copy_to_clipboard1 = Button(AES_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = clip)
    copy_to_clipboard1.place(x = 300, y= 360)
    box = 'aes_key'

    AES_frame.pack(fill=tk.BOTH,expand=TRUE)


def RSA_reset_page():

    global myCombo_key,First_box,second_box,box
    
    RSA_frame = tk.Frame(main_frame)

    manualset_btn = Button(RSA_frame, text = 'Manually reset\n new key', bg='#a9a99a', activeforeground='#0097e8', command=lambda: manually_setRSA_key(myCombo_key))
    manualset_btn.place(x=112,y=390)

    autoset_btn = Button(RSA_frame, text = 'Auto reset\n new key ', bg='#a9a9a9', activeforeground='#0097e8', command = auto_generate_rsakey)
    autoset_btn.place(x=215,y=390)

    key_options = ['RSA-2048','RSA-1024']
    myCombo_key = ttk.Combobox(RSA_frame, value= key_options)
    myCombo_key.current(0)
    myCombo_key.bind('<<ComboboxSelected>>')
    myCombo_key.delete(0,END)
    myCombo_key.insert(0,'select key pair')
    myCombo_key.place(x= 140, y=40)  

    First_box = tk.Text(RSA_frame, height=15, width=25, borderwidth=2)
    First_box.place(x=0, y=110)
    #First_box.insert(1.0,"Manual reset instructions: Enter the key you'd like to set it to here\n Auto reset instructions: press Auto generate button below")
    Labelone = Label(RSA_frame, text='(Private key)')
    Labelone.place(x=90, y=75)
    second_box = tk.Text(RSA_frame, height=15, width=25, borderwidth=2)
    second_box.place(x=210, y=110)
    #second_box.insert(1.0,"Instructions\n Manual reset: Type new \nkey here \n\n Auto reset: press 'Auto generate' button below")
    Labeltwo = Label(RSA_frame, text='(Public key)')
    Labeltwo.place(x=260, y=75)

    copy_to_clipboard1 = Button(RSA_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = lambda: clip_rsa_privkey())
    copy_to_clipboard1.place(x = 54, y= 360)
   
    copy_to_clipboard2 = Button(RSA_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = lambda: clip_rsa_pubkey())
    copy_to_clipboard2.place(x = 254, y = 360)
   
    RSA_frame.pack(fill=tk.BOTH,expand=TRUE)


def key_setting_page():
    global key_setting_frame,box,myCombo_key,key_text_box

    key_setting_frame = tk.Frame(main_frame)

    for row in range(12):
        empty_label = tk.Label(key_setting_frame, text='', bg='#c0c0c0')
        empty_label.grid(row=row, column=0, columnspan=4)

    key_text_box = Text(key_setting_frame, height = 17, width = 45)
    key_text_box.grid(row = 5, column = 0)
    key_text_box.insert(1.0,'\n\n\n\n\n\n\n          your key will appear here')

    key_options = ['AES-128','AES-192','AES-256','RSA-2048 (private)','RSA-2048 (public)','RSA-1024 (private)','RSA-1024 (public)']
    myCombo_key = ttk.Combobox(key_setting_frame, value= key_options)
    myCombo_key.current(0)
    myCombo_key.bind('<<ComboboxSelected>>')
    myCombo_key.delete(0,END)
    myCombo_key.insert(0,'select key')
    myCombo_key.place(x= 110, y=40)

    copy_to_clipboard = Button(key_setting_frame, text = 'Copy to clipboard', bd = 0, fg='black', activeforeground='#0097e8', command = lambda: clip_keyview())
    copy_to_clipboard.place(x = 254, y = 390)

    view_key_button = Button(key_setting_frame, text= 'Press to view key',width=13,height=3,bd=1, bg = '#c0c0c0',command = lambda: view_key())
    view_key_button.place(x=130,y=390)
    
    key_setting_frame.pack(fill=tk.BOTH,expand=TRUE)

def PBKDF2_Generate_pw():
    global password

    random_num = random.randint(12,18) #password will be minimum 12 characters
    len_password = int(random_num)  # getting length of password and converting it to an integer
    password = ''
            
    excluded_chars = []  # characters to exclude from the password generation if need be

    while len(password) < len_password:
            char = chr(randint(33, 126))
            if char not in excluded_chars:
                password += char
        
def Generate_pw(): 
    global pw_entry
    pw_entry.delete(0, tk.END)

    if Entry_box.get() == '':
        messagebox.showerror('Error', 'you must enter the number of characters before generating password.')
    else:
        len_password = int(Entry_box.get())  # getting length of password which the user wants to create and converting it to an integer
        password = ''

        excluded_chars = []  # characters to exclude from the password generation if need be

    while len(password) < len_password:          
        char = chr(randint(33, 126))
        if char not in excluded_chars:
            password += char

    pw_entry.insert(0, password)

#--------------------------------------------Fuctions for copying different text boxes from different pages to clipboard------------------------
def clip():
    if box == 'pwentry':
        root.clipboard_clear()
        root.clipboard_append(pw_entry.get())
    elif box == 'aes_key':
        root.clipboard_clear()
        root.clipboard_append(AES_key_box.get(1.0,'end'))

def clip_rsa_privkey():  #copying private key box from rsa key reset page
    root.clipboard_clear()
    root.clipboard_append(First_box.get(1.0,'end'))
def clip_rsa_pubkey():   #copying public key box from rsa key reset page
    root.clipboard_clear()
    root.clipboard_append(second_box.get(1.0,'end'))
def clip_keyview():     #copying view key box from key_setting reset page
    root.clipboard_clear()
    root.clipboard_append(key_text_box.get(1.0,'end'))
def clip_hashed_val():  #copying second box from hashing page to get hashed value
    root.clipboard_clear()
    root.clipboard_append(text_box_two.get(1.0,'end'))
def clip_encrypted_val(): #this function is to copy encrypted value from text box
    root.clipboard_clear()
    root.clipboard_append(myText.get(1.0,'end'))
def clip_decrypted_val(): #this function is to copy decrypted value from text box
    root.clipboard_clear()
    root.clipboard_append(myText_Decrypt.get(1.0,'end'))

#-----------------------------------------------------------------------------------------------------------------------------------------------------

def Generate_usr():
    usr_gen_box.delete(0,END)
    url = 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt' #list of strings to pull from to generate part of the username
    r = requests.get(url)
    txt = r.text
    split_words = txt.split() #seperating words into their own individual strings

    rand_num = randint(0, len(split_words) - 1)

    # Concatenate the word with the random number
    result = split_words[rand_num] + str(rand_num)
    
    usr_gen_box.insert(0, result)

def Genning_page():

    global pw_entry,Entry_box,usr_gen_box,box
    
    Genning_frame = tk.Frame(main_frame)

    num_chars = LabelFrame(Genning_frame, text='Enter the number of characters')
    num_chars.grid(row=0, pady=20)

    p = chr(randint(33, 126))

    Entry_box = Entry(num_chars)
    Entry_box.grid(row=0, pady=20, padx=20)

    pw_entry = Entry(Genning_frame, text='', bd=0, width=30)
    pw_entry.grid(row=1, pady=20)

    myframe = Frame(Genning_frame)
    myframe.grid(row=2, pady=20)

    Generate_pw_btn = Button(myframe, text='Generate password', width=15, height=2, command=lambda: Generate_pw())
    Generate_pw_btn.grid(column=0, row=0, padx=10)

    copy_to_clipboard1 = Button(myframe, text='Copy to clipboard', bd=0, fg='black', activeforeground='#0097e8',
                                command=clip) 
    copy_to_clipboard1.grid(row=0, column=1, padx=10)
    box = 'pwentry'


    lab = LabelFrame(Genning_frame, text='Username will appear here')
    lab.grid(row=3, pady=20)
    usr_gen_box = Entry(lab)
    usr_gen_box.grid(row=0, pady=20, padx=20)

    Generate_usr_btn = Button(Genning_frame, text='Generate username', width=15, height=2, command=lambda: Generate_usr())
    Generate_usr_btn.grid(row=4, pady=10)  # Use grid for consistency

   
    Genning_frame.pack(fill=tk.BOTH,expand=TRUE)

def create_instructions_frame(root):
    instructions_frame = tk.Frame(root, width=500, height=450, bg='#ffffff')
    
    instructions_text = """
    Encryption instructions:


    1. Select encryption algorithm from dropdown box.
    
    2. Either type what you want encrypted into the text box or press 'import txt file' which will import text in a file into the text box.
    
    3. Once text is in the box, press the 'encrypt' button below the dropdown box.
    
    4. You will either be prompted to export the encrypted data into the text box (for this option press no) or export the encrypted data in an external file (for this option press yes).

    


    Decryption instructions:

    
    1. Select algorithm from the dropdown box.
    
    2. Either type what you want decrypted into the text box or press 'import txt file' which will import text in a file into the text box.
    
    3. Once text is in the box, press the 'decrypt' button below the dropdown box.
    
    4. You will either be prompted to export the decrypted data into the text box (for this option press no) or export the decrypted data into an external file (for this option press yes).


    

    Hashing instructions:

    
    1. Select encryption algorithm from the dropdown box.
    
    2. Either type what you want to hash into the text box on the LEFT or press 'import txt file' which will import text in a file into the left text box.
    
    3. Once text is in the box, press the 'Hash' button below the dropdown box.
    
    4. The hashed value should then appear in the text box on the right.


    

    AES key reset instructions:


    1. Select the AES key which you'd like to reset from the dropdown menu.
    
    2. Press 'auto reset new key' button near the bottom of the page.
    
    3. Your new reset key should appear in the text box.

    


    RSA key reset instructions:

    
    1. Select the AES key pair which you'd like to reset from the dropdown menu.
    
    2. If you'd like to automatically generate a new key, simply press the 'auto reset new key' button. Otherwise, if you'd like to manually reset your new key, skip to step 5.
    
    3. You will then be prompted to continue to reset your key which will be permanently overwritten. Press 'yes' if you'd like to continue.
    
    4. Your new key pair should then appear in the text boxes.
    
    
    (NOTE: The steps after step 4 only refer to manual key resetting)
    
    5. Type your custom private key into the text box on the LEFT side.
    
    6. Type your custom public key into the text box on the RIGHT side.
    
    7. Press the 'manually reset new key' button.
    
    8. You'll be prompted, to continue to overwrite your current keypair press 'yes'.
    
    9. If your key change was successful, you should receive a popup messaging confirming success.
    """

    scroll_bar = tk.Scrollbar(instructions_frame)
    scroll_bar.pack(side='right', fill='y')

    text_box = tk.Text(instructions_frame, wrap='word', yscrollcommand=scroll_bar.set)
    text_box.insert('1.0', instructions_text)
    text_box.config(state = 'disabled')
    text_box.pack(fill='both', expand=True)

    scroll_bar.config(command=text_box.yview)

    return instructions_frame

def About_page():
    About_frame = tk.Frame(main_frame)
    About_frame.pack()

    # Add the instructions frame with scrollbar to the About_page frame
    instructions_frame = create_instructions_frame(About_frame)
    instructions_frame.pack()

#-------------------------------------creating navigation elements/animation for splash page ----------------------------------------
def hide_indicators():
    Encryption_indicator.config(bg ='#a9a9a9')
    Decryption_indicator.config(bg ='#a9a9a9')
    hash_indicator.config(bg ='#a9a9a9')
    key_manager_indicator.config(bg ='#a9a9a9')
    random_indicator.config(bg ='#a9a9a9')
    about_indicator.config(bg ='#a9a9a9')
    AES_indicator.config(bg ='#a9a9a9')
    RSA_indicator.config(bg ='#a9a9a9')

def indicate(lb, page):
    hide_indicators()
    lb.config(bg= 'black')
    clear_pages()
    page()

def animate_dots():
   for i in range(2):
       dot_label = Label(splash_root, image=dot_images[i], bg='black')
       dot_label.place(x=180 + (i * 15), y=150)
       splash_root.update_idletasks()
       time.sleep(0.5)
       dot_label.destroy()
#---------------------------------------------------------------------Signup page-----------------------------------------------------
def signup_screen():
   global signup_frame
   clear_pages()

   update_sidemenu_visibility()  
   signup_frame =tk.Frame(main_frame,bg='#c0c0c0')
   
   logging_menu_fm=tk.Frame(signup_frame,bg='#c0c0c0')
   logging_menu_fm.pack()
   logging_menu_fm.pack_propagate(False)
   logging_menu_fm.configure(width =500, height=35)

   label = Label(signup_frame, text='CREATE AN ACCOUNT', font='BarlowCondensed-Medium',bg='#d3d3d3',fg='black').pack(pady=10,padx=10)

   signup_nav = tk.Button(signup_frame, text = 'Signup',bd=0,activeforeground='#0097e8',command= signup_screen,fg='black',font=('Arial', 12),width=13,cursor='hand2')
   signup_nav.place(x=0,y=0)
   signup_indicator = tk.Label(signup_frame, text="", bg='#a9a9a9') #making the colour of the indicator the same background colour as the button so it dosent change unless the button was been pressed
   signup_indicator.place(x=10, y=25, width=65, height=5) #placing indicator next to the page navigation button

   login_navigation= tk.Button(signup_frame, text = 'Login',bd=0,activeforeground='#0097e8',command = login_screen,fg='black',font=('Arial', 12),width=13,cursor='hand2')
   login_navigation.place(x=100,y=0)
   login_indicator = tk.Label(signup_frame, text="", bg='#a9a9a9') #making the colour of the indicator the same background colour as the button so it dosent change unless the button was been pressed
   login_indicator.place(x=120, y=25, width=65, height=5) #placing indicator next to the page navigation button 

   signup_button = Button(signup_frame, text='Signup', fg='black', command = lambda: signup(passwbox.get(),userbox.get()), bg='#d3d3d3', width=12,cursor='hand2')
   signup_button.place(x=160, y=280)
   
   userbox = Entry(signup_frame,width=30,borderwidth=3,fg='black')
   userbox.pack(padx=100,pady=50)
   passwbox = Entry(signup_frame,width=30,borderwidth=3,fg='black',show='*')
   passwbox.pack()

   user_field = Label(signup_frame,text='USERNAME:',fg='black',bg='#c0c0c0').place(x=40,y=135)
   passwbox_field = Label(signup_frame, text='PASSWORD:',fg='black',bg='#c0c0c0').place(x=40,y=210)

   return_to_login_button = Button(signup_frame, text='Click here to return to login page', fg='black',command=login_screen, bg='#c0c0c0',bd=0,cursor='hand2')
   return_to_login_button.place(x=120, y=360)

   signup_frame.pack(fill=tk.BOTH,expand=TRUE)

#----------------------------------------------------------Login page--------------------------------------------------------------------------
def login_screen():   # x-30 ,,,  y+30
   #can be accessed by other functions
   global userbox,passwbox,logging_in_frame, signup_indicator,login_indicator
    
   splash_root.withdraw() #hides the splash screen once this page is opened. destroying causes error in navigating signup/signin menu
   clear_pages()
   logging_in_frame = tk.Frame(main_frame,bg='#c0c0c0')
   
   logging_menu_fm=tk.Frame(logging_in_frame,bg='#c0c0c0')
   logging_menu_fm.pack()
   logging_menu_fm.pack_propagate(False)
   logging_menu_fm.configure(width =500, height=35)

   signup_nav = tk.Button(logging_menu_fm, text = 'Signup',bd=0,activeforeground='#0097e8',command= signup_screen,fg='black',font=('Arial', 12),width=13,cursor='hand2')
   signup_nav.place(x=0,y=0)
   signup_indicator = tk.Label(logging_in_frame, text="", bg='#a9a9a9') #making the colour of the indicator the same background colour as the button so it dosent change unless the button was been pressed
   signup_indicator.place(x=10, y=25, width=65, height=5) #placing indicator next to the page navigation button

   login_navigation= tk.Button(logging_menu_fm, text = 'Login',bd=0,activeforeground='#0097e8',command = login_screen,fg='black',font=('Arial', 12),width=13,cursor='hand2')
   login_navigation.place(x=100,y=0)
   login_indicator = tk.Label(logging_in_frame, text="", bg='#a9a9a9') #making the colour of the indicator the same background colour as the button so it dosent change unless the button was been pressed
   login_indicator.place(x=120, y=25, width=65, height=5) #placing indicator next to the page navigation button 

   label = Label(logging_in_frame, text='ACCESS PORTAL', font='BarlowCondensed-Medium',bg='#d3d3d3',fg='black').pack(pady=10,padx=10)

   userbox = Entry(logging_in_frame,width=30,borderwidth=3,fg='black')
   userbox.pack(padx=100,pady=50)
   passwbox = Entry(logging_in_frame,width=30,borderwidth=3,fg='black',show='*')
   passwbox.pack()

   user_field = Label(logging_in_frame,text='USERNAME:',fg='black',bg='#c0c0c0').place(x=40,y=135)
   passwbox_field = Label(logging_in_frame, text='PASSWORD:',fg='black',bg='#c0c0c0').place(x=40,y=210)

   log_button = Button(logging_in_frame, text='Login', command= lambda: logon(passwbox.get(),userbox.get()), fg='black', bg='#d3d3d3', width=12,cursor='hand2')
   log_button.place(x=205, y=210)
   log_button.pack(padx=30, pady=30)

   signup_button = Button(logging_in_frame, text='Dont already have an account? Sign up here',command=signup_screen, fg='black', bg='#c0c0c0',bd=0,cursor='hand2')
   signup_button.place(x=350, y=300)
   signup_button.pack(padx=30, pady=30)

   logging_in_frame.pack(fill=tk.BOTH,expand=TRUE)
   update_sidemenu_visibility()

#--------------------------------------------------------------------------------------------------------------------------------
authenticated = False

def update_authentication_status(status):
    global authenticated
    authenticated = status
    update_sidemenu_visibility()

# Function to update the visibility of the main tools sidemenu depending on user authenetication
def update_sidemenu_visibility():
    if authenticated:
        sidemenu_frame.pack(side="left")
    else:
        sidemenu_frame.pack_forget()

#--------------------------------------------------Account login function--------------------------------------------------------
def logon(passwbox,userbox): 
   username = userbox
   password = passwbox

   if username != '' and password != '':
       c.execute('SELECT password FROM users WHERE username=?',[username])
       result = c.fetchone()
       if result:
           if bcrypt.checkpw(password.encode('utf-8'),result[0]):
               update_authentication_status(True)
               encryption_page()
               messagebox.showinfo('successful','You have been logged in successfully')
           else:
               messagebox.showinfo('Logon','Incorrect username or password')
   else:
       messagebox.showerror('oops','looks like you missed something')
#--------------------------------------------------Signup password validation-----------------------------------------------------
def validate_password(password):
    if len(password) < 8:
        return False
    else:
        return True

#--------------------------------------------------Account signup function----------------------------------------------------------
def signup(passwbox,userbox):
    username = userbox
    password = passwbox

    validated = validate_password(password)  # Check password validation

    if validated:
        # Before hashing, encode the password using utf-8
        encoded_password = password.encode('utf-8')
        # Salt the password to hash it
        hashed_password = bcrypt.hashpw(encoded_password, bcrypt.gensalt())

        if username != '' and password != '':
            c.execute('SELECT username FROM users WHERE username=?', [username])
            if c.fetchone() is not None:
                messagebox.showerror('Error', 'Username already exists')
                return
            else:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed_password])
                conn.commit()
                messagebox.showinfo('Success', 'Your account has been successfully created')
    else:
        messagebox.showerror('Oops', 'Your password must be a minimum of 8 characters')

#--------------------------------------------creating database conncection----------------------------------------------------------------------
conn = sqlite3.connect('credentials.db')
c  = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users (
          username TEXT NOT NULL,
          password TEXT NOT NULL

          )''')

conn.commit()
#---------------------------------------------------------------------------Making splash window-------------------------------------------------------
splash_root = Tk()
splash_root.title('OBSICURITY - Exchange data with privacy')
splash_root.geometry('500x250')
splash_root.iconbitmap('black white logo.ico')
splash_root.configure(bg='black')

# Making custom font for text on splash window
custom_font = ('BarlowCondensed-Medium')

# Putting text on the splash window
splash_label = Label(splash_root, text='OBSICURITY', bg='black', fg='white')
splash_label.configure(font=(custom_font, '30', 'bold'))
splash_label.pack(pady=100)

splash_label2 = Label(splash_root, text='Loading...', fg='white', bg='black')
splash_label2.configure(font=('Calibri', 11))
splash_label2.place(x=10, y=200)

# Load images for the dots
dot_images = [ImageTk.PhotoImage(Image.open('Frame 1.png')),
             ImageTk.PhotoImage(Image.open('Frame 2.png'))]

# Animate the dots for 5 cycles
for _ in range(7):
   animate_dots()

# Close the splash screen and open the login screen after 9 seconds
splash_root.after(1000,login_screen)

#----------------------------------------------------------------------------------------------------------------------------------------------------------

root = tk.Tk()
root.title('OBSICURITY')
root.geometry('500x450')
root.iconbitmap('black white logo.ico')
root.configure(bg='#c0c0c0')
root.resizable(width=False,height=False) #making the window a fixed size


#creating the mainframe which all the different pages will be put into/hosted on
main_frame = tk.Frame(root)
main_frame.pack(side = tk.RIGHT)
main_frame.pack_propagate(False)
main_frame.configure(height=700, width=425, bg='#c0c0c0')

#---------------------------Creating side menu for the tools main page --------------------------------------------------------------------------------------------------

sidemenu_frame = tk.Frame(root, bg='#a9a9a9')
sidemenu_frame.pack_propagate(False)
sidemenu_frame.configure(width=80, height=450)  # Use a larger size
sidemenu_frame.pack(side="left")

# adding content to the frame (e.g labels and buttons)
label = tk.Label(sidemenu_frame)
label.pack()

Encry_btn = tk.Button(sidemenu_frame, text=" Encryption ", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2, width= 8, command = lambda: indicate(Encryption_indicator, encryption_page))  #creating/designing button, the command leads to the navigation of the intended page and the page navigation design fo usability purpose
Encry_btn.place(x=10, y=10) #positioning the button on the sidemenu frame
Encryption_indicator = tk.Label(sidemenu_frame, text="", bg='#a9a9a9') #making the colour of the indicator the same background colour as the button so it dosent change unless the button was been pressed
Encryption_indicator.place(x=3, y=10, width=5, height=40) #placing indicator next to the page navigation button

Decry_btn = tk.Button(sidemenu_frame, text="Decryption", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2, width= 8, command=lambda: indicate(Decryption_indicator,Decryption_page ))
Decry_btn.place(x=10, y=70)
Decryption_indicator = tk.Label(sidemenu_frame, text="", bg='#a9a9a9' )
Decryption_indicator.place(x=3, y=70, width=5, height=40)
 
hash_btn = tk.Button(sidemenu_frame, text="Hashing", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2, width= 8, command = lambda: indicate(hash_indicator,Hashing_page) )
hash_btn.place(x=10, y=130)
hash_indicator = tk.Label(sidemenu_frame, text="", bg='#a9a9a9')
hash_indicator.place(x=3, y=130, width=5, height=40)
 
AES_reset = tk.Button(sidemenu_frame, text="AES reset", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2, width= 8, command = lambda: indicate(AES_indicator,AES_reset_page) )
AES_reset.place(x=10, y=180)
AES_indicator = tk.Label(sidemenu_frame, text="", bg='#a9a9a9')
AES_indicator.place(x=3, y=180, width=5, height=40)

RSA_reset = tk.Button(sidemenu_frame, text="RSA reset", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2, width= 8, command = lambda: indicate(RSA_indicator,RSA_reset_page) )
RSA_reset.place(x=10, y=230)
RSA_indicator = tk.Label(sidemenu_frame, text="", bg='#a9a9a9')
RSA_indicator.place(x=3, y=230, width=5, height=40)

key_management_btn = tk.Button(sidemenu_frame, text="View keys", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2, command = lambda:indicate(key_manager_indicator,key_setting_page))
key_management_btn.place(x=10, y=280)
key_manager_indicator = tk.Label(sidemenu_frame, text="", bg='#a9a9a9')
key_manager_indicator.place(x=3, y=280, width=5, height=40)

random_generation_btn = tk.Button(sidemenu_frame, text="Genning", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9', height = 2,width= 8, command = lambda:indicate(random_indicator,Genning_page))
random_generation_btn.place(x=10, y=330)
random_indicator = tk.Label(sidemenu_frame, text="",bg='#a9a9a9')
random_indicator.place(x=3, y=330, width=5, height=40)

about_btn = tk.Button(sidemenu_frame, text="About", font=('Bold', '10'), fg='black',bd=0,bg='#a9a9a9',height = 2, width= 8, command = lambda:indicate(about_indicator,About_page))
about_btn.place(x=10, y=380)
about_indicator = tk.Label(sidemenu_frame, text="",bg='#a9a9a9')
about_indicator.place(x=3, y=380, width=5, height=40)

root.mainloop()

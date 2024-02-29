#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File: AES_CBC.py
Description: This program accepts English text and encrypts/decrypts it using the AES block cipher in CBC mode.

Install Notes: Use "python3 -m pip install PyCryptodome" (Crypto import statement) or "python3 -m pip install PyCryptodomex" (Cryptodome statement) to install library dependencies (URL REF: https://pycryptodome.readthedocs.io/en/latest/src/installation.html).
"""

# Import statements
import sys
import string
import os
import cryptography

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


# Global variables
letters = string.ascii_letters + " "

def main(args):
    print(f"This script encrypts your plaintext using the AES block cipher in CBC mode and also decrypts it for you as well. The supported characters are: {letters}.")
    
    cleartext = input_handler()
    
    print(f"Running the AES block cipher in CBC mode based on this text '{cleartext}'. Please wait...\n")

    cleartext_data = cleartext.encode('utf-8')
    
    key, iv_key = key_iv_Gen()
    
    ciphertext = encrypt(cleartext_data, key, iv_key)
    print(f"Raw ciphertext encrypted data (Hex): {ciphertext.hex()}")

    decrypted_plaintext = decrypt(iv_key, ciphertext, key).decode('utf-8')
    print(f"\nYour decrypted data: {decrypted_plaintext}\n")

    del key, iv_key, cleartext_data, ciphertext, decrypted_plaintext
    print("AES block cipher in CBC mode implementation complete.\n")
    
def input_handler():
    cleartext = input("\nEnter your cleartext here: ")
    if cleartext != "":
        if all(char in letters for char in cleartext):
            print(f"\nConfirming input: {cleartext}\n")
        else:
            print("\nInvalid input. Ending.\n")
            sys.exit()
    else:
        print("\nNo input detected. Please run again.\n")
        sys.exit()
    
    return cleartext

def key_iv_Gen():
    key_gen = get_random_bytes(32) # AES-256 key
    iv_gen = get_random_bytes(16) # Saw that I can also use "AES.block_size" instead of 16 but I like the defined number.
    
    return key_gen, iv_gen

def encrypt(plaintext, key, iv_key):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv_key)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        return ciphertext
    
    except Exception as error:
        print(f"Encountered an error during encryption: {error}")
        sys.exit()

def decrypt(iv, ciphertext, key):
    try:
        decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = unpad(decrypt_cipher.decrypt(ciphertext), AES.block_size)
        
        return plain_text
    
    except Exception as error:
        print(f"Encountered an error during decryption: {error}")
        sys.exit()

if __name__ == '__main__':
    main(sys.argv[1:])
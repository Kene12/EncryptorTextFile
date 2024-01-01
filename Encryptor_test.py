from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from tkinter import filedialog
import tkinter as tk
import art

def pad(text):
    # Add PKCS7 padding to the text
    block_size = DES.block_size
    padding_length = block_size - (len(text) % block_size)
    return text + bytes([padding_length] * padding_length)

def unpad(padded_text):
    # Remove PKCS7 padding from the text
    padding_length = padded_text[-1]
    return padded_text[:-padding_length]

def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = cipher.decrypt(ciphertext)
    return unpad(padded_text)

def generate_des_key():
    # Generate a random 8-byte key for DES
    return get_random_bytes(8)

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)
    print("Key saved to file:", filename)

def read_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

def print_menu():
    print(art.text2art("Encrypt and Decrypt"))  # Assuming 'art' is a module for ASCII art
    print("\n[-] SELECT AN OPTION TO BEGIN: [-]\n\n1. File Encrypt\n2. Decrypt\n3. Generate and Save Key\n4. Read Key from File\n5. Exit")

def encrypt_file():
    root = tk.Tk()
    root.withdraw()

    input_filename = filedialog.askopenfilename(title="Select input file", filetypes=[("Text files", "*.txt")])
    if not input_filename:
        print("No input file selected. Exiting.")
        return

    output_filename = filedialog.asksaveasfilename(title="Select output file", defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
    if not output_filename:
        print("No output file selected. Exiting.")
        return

    key = generate_des_key()

    with open(input_filename, 'rb') as file:
        plaintext = file.read()

    ciphertext = des_encrypt(key, plaintext)

    with open(output_filename, 'wb') as file:
        file.write(ciphertext)

    print("File encrypted and saved to:", output_filename)
    print("Encryption Key:", key.hex())

def decrypt_file():
    root = tk.Tk()
    root.withdraw()

    input_filename = filedialog.askopenfilename(title="Select input file", filetypes=[("Encrypted files", "*.enc")])
    if not input_filename:
        print("No input file selected. Exiting.")
        return

    output_filename = filedialog.asksaveasfilename(title="Select output file", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if not output_filename:
        print("No output file selected. Exiting.")
        return

    key_hex = input("Enter the encryption key (in hex): ")
    key = bytes.fromhex(key_hex)

    with open(input_filename, 'rb') as file:
        ciphertext = file.read()

    plaintext = des_decrypt(key, ciphertext)

    with open(output_filename, 'wb') as file:
        file.write(plaintext)

    print("File decrypted and saved to:", output_filename)

def generate_and_save_key():
    key = generate_des_key()
    output_filename = filedialog.asksaveasfilename(title="Save Key to File", defaultextension=".key", filetypes=[("Key files", "*.key")])
    if not output_filename:
        print("No output file selected. Exiting.")
        return

    save_key_to_file(key, output_filename)

def read_key():
    key_file = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])
    if not key_file:
        print("No key file selected. Exiting.")
        return
    key = read_key_from_file(key_file)
    print("Key read successfully:", key.hex())

# Example usage:
while True:
    print_menu()
    choice = input("Enter your choice (1, 2, 3, 4, or 5): ")

    if choice == '1':
        encrypt_file()
    elif choice == '2':
        decrypt_file()
    elif choice == '3':
        generate_and_save_key()
    elif choice == '4':
        read_key()
    elif choice == '5':
        exit()
    else:
        print("Invalid choice. Please try again.")
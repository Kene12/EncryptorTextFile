# Import necessary modules
from Crypto.Cipher import DES  # Using DES encryption algorithm from PyCryptoDome library
from Crypto.Random import get_random_bytes  # For generating random bytes for the key
from tkinter import filedialog  # For file dialogs in a GUI environment
import tkinter as tk  # Tkinter for creating GUI windows
import art  # For ASCII art

# Padding functions for PKCS7 padding scheme
def pad(text):
    # Add PKCS7 padding to the text
    block_size = DES.block_size
    padding_length = block_size - (len(text) % block_size)
    return text + bytes([padding_length] * padding_length)

def unpad(padded_text):
    # Remove PKCS7 padding from the text
    padding_length = padded_text[-1]
    return padded_text[:-padding_length]

# Function for DES encryption
def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)  # Create a DES cipher object
    padded_text = pad(plaintext)  # Pad the plaintext
    ciphertext = cipher.encrypt(padded_text)  # Encrypt the padded plaintext
    return ciphertext

# Function for DES decryption
def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)  # Create a DES cipher object
    padded_text = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    return unpad(padded_text)  # Unpad the decrypted text

# Function to generate a random DES key
def generate_des_key():
    # Generate a random 8-byte key for DES
    return get_random_bytes(8)

# Function to save the key to a file
def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)
    print("Key saved to file:", filename)

# Function to read the key from a file
def read_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

# Function to print the menu options
def print_menu():
    print(art.text2art("Encrypt and Decrypt"))  # ASCII art for title
    print("\n[-] SELECT AN OPTION TO BEGIN: [-]\n\n1. File Encrypt\n2. Decrypt\n3. Generate and Save Key\n4. Read Key from File\n5. Exit")

# Function to encrypt a file
def encrypt_file():
    # Create a Tkinter root window (this is used for file dialogs)
    root = tk.Tk()
    root.withdraw()

    # Ask the user to select an input file
    input_filename = filedialog.askopenfilename(title="Select input file", filetypes=[("Text files", "*.txt")])

    # Check if the user canceled the file selection
    if not input_filename:
        print("No input file selected. Exiting.")
        return

    # Ask the user to select an output file
    output_filename = filedialog.asksaveasfilename(title="Select output file", defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])

    # Check if the user canceled the file selection
    if not output_filename:
        print("No output file selected. Exiting.")
        return

    # Check if the user wants to generate and save a new key
    generate_key_option = input("Do you want to generate a new key? (y/n): ").lower()

    if generate_key_option == 'y':
        # Generate a new DES key
        key = generate_des_key()

        # Ask the user to select a file to save the key
        key_filename = filedialog.asksaveasfilename(title="Save Key to File", defaultextension=".key", filetypes=[("Key files", "*.key")])

        # Check if the user canceled the key file selection
        if not key_filename:
            print("No key file selected. Exiting.")
            return

        # Save the key to the selected file
        save_key_to_file(key, key_filename)

        # Print information about the key generation
        print("New key generated and saved to:", key_filename)
    else:
        # Ask the user to select an existing key file
        key_filename = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])

        # Check if the user canceled the key file selection
        if not key_filename:
            print("No key file selected. Exiting.")
            return

        # Read the key from the selected file
        key = read_key_from_file(key_filename)

        # Print information about using an existing key
        print("Using existing key from:", key_filename)

    # Read the plaintext from the input file
    with open(input_filename, 'rb') as file:
        plaintext = file.read()

    # Encrypt the plaintext using DES
    ciphertext = des_encrypt(key, plaintext)

    # Write the encrypted ciphertext to the output file
    with open(output_filename, 'wb') as file:
        file.write(ciphertext)

    # Print information about the encryption
    print("File encrypted and saved to:", output_filename)
    print("Encryption Key:", key.hex())

# Function to decrypt a file
def decrypt_file():
    root = tk.Tk()
    root.withdraw()

    input_filename = filedialog.askopenfilename(title="Select input file", filetypes=[("Encrypted files", "*.enc")])
    if not input_filename:
        print("No input file selected. Exiting.")
        return

    key_filename = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])
    if not key_filename:
        print("No key file selected. Exiting.")
        return

    key = read_key_from_file(key_filename)

    output_filename = filedialog.asksaveasfilename(title="Select output file", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if not output_filename:
        print("No output file selected. Exiting.")
        return

    with open(input_filename, 'rb') as file:
        ciphertext = file.read()

    plaintext = des_decrypt(key, ciphertext)

    with open(output_filename, 'wb') as file:
        file.write(plaintext)

    print("File decrypted and saved to:", output_filename)

# Function to generate and save a key
def generate_and_save_key():
    key = generate_des_key()
    output_filename = filedialog.asksaveasfilename(title="Save Key to File", defaultextension=".key", filetypes=[("Key files", "*.key")])
    if not output_filename:
        print("No output file selected. Exiting.")
        return

    save_key_to_file(key, output_filename)

# Function to read a key from a file
def read_key():
    key_file = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])
    if not key_file:
        print("No key file selected. Exiting.")
        return
    key = read_key_from_file(key_file)
    print("Key read successfully:", key.hex())

# Example usage:
while True:
    print_menu()  # Display the menu
    choice = input("Enter your choice (1, 2, 3, 4, or 5): ")  # Ask for user input

    # Perform actions based on user choice
    if choice == '1':
        encrypt_file()  # Encrypt a file
    elif choice == '2':
        decrypt_file()  # Decrypt a file
    elif choice == '3':
        generate_and_save_key()  # Generate and save a key
    elif choice == '4':
        read_key()  # Read a key from a file
    elif choice == '5':
        exit()  # Exit the program
    else:
        print("Invalid choice. Please try again.")  # Invalid choice message

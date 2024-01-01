from tkinter import filedialog
from cryptography.fernet import Fernet
import art  # Import the art library
import sys
import os

script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

def generate_key():
    return Fernet.generate_key()

def save_key(key, key_file):
    with open(key_file, 'wb') as key_file:
        key_file.write(key)

def load_key(key_file):
    try:
        with open(key_file, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        print("Key file not found.")
        return None

def load_key_and_generate_key():
    key = load_key("secret.key")
    if key is None:
        key = generate_key()
        save_key(key, "secret.key")
        print(f"Generated Key: {key}")
    return key

def remove_key_file(key_file):
    if os.path.exists(key_file):
        try:
            os.remove(key_file)
            print("Key file removed.")
        except Exception as e:
            print(f"Error removing key file: {e}")
    else:
        print("Key file not found.")

def encrypt_text_file(key, input_file, output_file):
    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher_suite.encrypt(plaintext)
    with open(output_file, 'wb') as file:
        file.write(ciphertext)

def decrypt_text_file(key, input_file):
    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        ciphertext = file.read()
    plaintext = cipher_suite.decrypt(ciphertext)

    save_decrypted_content = filedialog.asksaveasfilename(defaultextension=".txt",
                                                           filetypes=[("Text files", "*.txt")])

    if save_decrypted_content:
        with open(save_decrypted_content, 'wb') as file:
            file.write(plaintext)
        print(f"Decrypted content saved to {save_decrypted_content}")
    else:
        print("Decryption cancelled.")

def print_menu():
    print(art.text2art("Encrypt and Decrypt"))  # Use art for ASCII art
    print("\n[-] SELECT AN OPTION TO BEGIN: [-]\n\n1. Load key and generate key\n2. Encrypt\n3. Decrypt\n4. Remove key\n5. Exit")

def main():
    while True:
        print_menu()
        choice = input("Enter your choice (1/2/3/4/5): ")

        if choice == '1':
            # Load key and generate key option
            key = load_key_and_generate_key()

        elif choice == '2':
            # Encryption option
            key = load_key_and_generate_key()
            input_file = filedialog.askopenfilename(title="Select Input File")
            output_file = filedialog.asksaveasfilename(defaultextension=".enc",
                                                        filetypes=[("Encrypted files", "*.enc")])
            encrypt_text_file(key, input_file, output_file)
            print(f"File encrypted and saved to {output_file}")

        elif choice == '3':
            # Decryption option
            key = load_key_and_generate_key()
            input_file = filedialog.askopenfilename(title="Select Encrypted File")
            decrypt_text_file(key, input_file)

        elif choice == '4':
            # Remove key option
            confirm = input("Are you sure you want to remove the key file? (y/n): ").lower()
            if confirm == 'y':
                remove_key_file("secret.key")
            else:
                print("Key removal cancelled.")

        elif choice == '5':
            # Exit
            print("Exiting program. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    main()
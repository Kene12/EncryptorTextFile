from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from tkinter import filedialog, Tk, Label, Button, StringVar, Entry, messagebox
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

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption App")

        self.choice_var = StringVar()
        self.create_ui()

    def create_ui(self):
        Label(self.root, text=art.text2art("Encrypt and Decrypt")).pack(pady=10)

        Button(self.root, text="Encrypt File", command=self.encrypt_file).pack()
        Button(self.root, text="Decrypt File", command=self.decrypt_file).pack()
        Button(self.root, text="Generate and Save Key", command=self.generate_and_save_key).pack()
        Button(self.root, text="Read Key", command=self.read_key).pack()
        Button(self.root, text="Exit", command=self.root.destroy).pack(pady=10)

    def encrypt_file(self):
        root = Tk()
        root.withdraw()

        input_filename = filedialog.askopenfilename(title="Select input file", filetypes=[("Text files", "*.txt")])

        if not input_filename:
            messagebox.showinfo("Error", "No input file selected. Exiting.")
            return

        output_filename = filedialog.asksaveasfilename(title="Select output file", defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])

        if not output_filename:
            messagebox.showinfo("Error", "No output file selected. Exiting.")
            return

        generate_key_option = messagebox.askquestion("Key Generation", "Do you want to generate a new key?")

        if generate_key_option == 'yes':
            key = generate_des_key()
            key_filename = filedialog.asksaveasfilename(title="Save Key to File", defaultextension=".key", filetypes=[("Key files", "*.key")])

            if not key_filename:
                messagebox.showinfo("Error", "No key file selected. Exiting.")
                return

            save_key_to_file(key, key_filename)
            messagebox.showinfo("Key Information", "New key generated and saved to:\n" + key_filename)
        else:
            key_filename = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])

            if not key_filename:
                messagebox.showinfo("Error", "No key file selected. Exiting.")
                return

            key = read_key_from_file(key_filename)
            messagebox.showinfo("Key Information", "Using existing key from:\n" + key_filename)

        with open(input_filename, 'rb') as file:
            plaintext = file.read()

        ciphertext = des_encrypt(key, plaintext)

        with open(output_filename, 'wb') as file:
            file.write(ciphertext)

        messagebox.showinfo("Encryption Information", "File encrypted and saved to:\n" + output_filename + "\nEncryption Key:\n" + key.hex())
        root.destroy()

    def decrypt_file(self):
        root = Tk()
        root.withdraw()

        input_filename = filedialog.askopenfilename(title="Select input file", filetypes=[("Encrypted files", "*.enc")])

        if not input_filename:
            messagebox.showinfo("Error", "No input file selected. Exiting.")
            return

        key_filename = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])

        if not key_filename:
            messagebox.showinfo("Error", "No key file selected. Exiting.")
            return

        key = read_key_from_file(key_filename)

        output_filename = filedialog.asksaveasfilename(title="Select output file", defaultextension=".txt", filetypes=[("Text files", "*.txt")])

        if not output_filename:
            messagebox.showinfo("Error", "No output file selected. Exiting.")
            return

        with open(input_filename, 'rb') as file:
            ciphertext = file.read()

        plaintext = des_decrypt(key, ciphertext)

        with open(output_filename, 'wb') as file:
            file.write(plaintext)

        messagebox.showinfo("Decryption Information", "File decrypted and saved to:\n" + output_filename)
        root.destroy()

    def generate_and_save_key(self):
        key = generate_des_key()
        output_filename = filedialog.asksaveasfilename(title="Save Key to File", defaultextension=".key", filetypes=[("Key files", "*.key")])

        if not output_filename:
            messagebox.showinfo("Error", "No output file selected. Exiting.")
            return

        save_key_to_file(key, output_filename)
        messagebox.showinfo("Key Information", "New key generated and saved to:\n" + output_filename)

    def read_key(self):
        key_file = filedialog.askopenfilename(title="Select key file", filetypes=[("Key files", "*.key")])

        if not key_file:
            messagebox.showinfo("Error", "No key file selected. Exiting.")
            return

        key = read_key_from_file(key_file)
        messagebox.showinfo("Key Information", "Key read successfully:\n" + key.hex())

def main():
    root = Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

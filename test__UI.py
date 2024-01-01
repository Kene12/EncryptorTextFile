from tkinter import Tk, Label, Button, filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken
from tqdm import tqdm
import art
import os

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
    try:
        # Attempt to instantiate Fernet with the loaded key to check its validity
        Fernet(key)
    except (ValueError, TypeError):
        # If instantiation fails, generate a new key
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

    # Initialize the progress bar
    progress_bar = tqdm(total=len(plaintext), unit='B', unit_scale=True, desc='Encrypting')

    ciphertext = b''
    for chunk in tqdm(range(0, len(plaintext), 1024), unit='B', unit_scale=True, desc='Encrypting'):
        chunk_data = plaintext[chunk:chunk + 1024]
        ciphertext += cipher_suite.encrypt(chunk_data)
        progress_bar.update(len(chunk_data))

    progress_bar.close()

    with open(output_file, 'wb') as file:
        file.write(ciphertext)

def decrypt_text_file(key, input_file):
    cipher_suite = Fernet(key)
    with open(input_file, 'rb') as file:
        ciphertext = file.read()

    try:
        plaintext = cipher_suite.decrypt(ciphertext)
    except InvalidToken:
        print("Decryption failed. The provided key is not accurate.")
        return

    save_decrypted_content = filedialog.asksaveasfilename(defaultextension=".txt",
                                                           filetypes=[("Text files", "*.txt")])

    if save_decrypted_content:
        with open(save_decrypted_content, 'wb') as file:
            file.write(plaintext)
        print(f"Decrypted content saved to {save_decrypted_content}")
    else:
        print("Decryption cancelled.")
        
class EncryptDecryptApp:
    def __init__(self, master):
        self.master = master
        master.title("Encrypt and Decrypt App")
        
        self.key = None

        self.label = Label(master, text=art.text2art("Encrypt and Decrypt"))
        self.label.pack()

        self.load_key_button = Button(master, text="1. Load key and generate key", command=self.load_key_and_generate_key)
        self.load_key_button.pack()

        self.encrypt_button = Button(master, text="2. Encrypt", command=self.encrypt_text_file)
        self.encrypt_button.pack()

        self.decrypt_button = Button(master, text="3. Decrypt", command=self.decrypt_text_file)
        self.decrypt_button.pack()

        self.remove_key_button = Button(master, text="4. Remove key", command=self.remove_key_file)
        self.remove_key_button.pack()

        self.exit_button = Button(master, text="5. Exit", command=master.quit)
        self.exit_button.pack()

    
    
    def load_key_and_generate_key(self):
        key = load_key("secret.key")
        try:
            Fernet(key)
        except (ValueError, TypeError):
            key = generate_key()
            save_key(key, "secret.key")
            messagebox.showinfo("Key Loaded", f"Generated Key: {key}")
        self.key = key

    def remove_key_file(self):
        confirm = messagebox.askyesno("Remove Key", "Are you sure you want to remove the key file?")
        if confirm:
            remove_key_file("secret.key")
            messagebox.showinfo("Key Removed", "Key file removed.")
        else:
            messagebox.showinfo("Key Removal Cancelled", "Key removal cancelled.")

    def encrypt_text_file(self):
        if not self.key:
            messagebox.showerror("Key Missing", "Please load or generate a key.")
            return

        input_file = filedialog.askopenfilename(title="Select Input File")
        if not input_file:
            return

        output_file = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
        if not output_file:
            return

        cipher_suite = Fernet(self.key)
        with open(input_file, 'rb') as file:
            plaintext = file.read()

        progress_bar = tqdm(total=len(plaintext), unit='B', unit_scale=True, desc='Encrypting')
        ciphertext = b''

        for chunk in tqdm(range(0, len(plaintext), 1024), unit='B', unit_scale=True, desc='Encrypting'):
            chunk_data = plaintext[chunk:chunk + 1024]
            ciphertext += cipher_suite.encrypt(chunk_data)
            progress_bar.update(len(chunk_data))

        progress_bar.close()

        with open(output_file, 'wb') as file:
            file.write(ciphertext)

        messagebox.showinfo("Encryption Complete", f"File encrypted and saved to {output_file}")

    def decrypt_text_file(self):
        if not self.key:
            messagebox.showerror("Key Missing", "Please load or generate a key.")
            return

        input_file = filedialog.askopenfilename(title="Select Encrypted File")
        if not input_file:
            return

        cipher_suite = Fernet(self.key)
        with open(input_file, 'rb') as file:
            ciphertext = file.read()

        try:
            plaintext = cipher_suite.decrypt(ciphertext)
        except InvalidToken:
            messagebox.showerror("Decryption Failed", "Decryption failed. The provided key is not accurate.")
            return

        save_decrypted_content = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])

        if save_decrypted_content:
            with open(save_decrypted_content, 'wb') as file:
                file.write(plaintext)
            messagebox.showinfo("Decryption Complete", f"Decrypted content saved to {save_decrypted_content}")
        else:
            messagebox.showinfo("Decryption Cancelled", "Decryption cancelled.")

if __name__ == "__main__":
    root = Tk()
    app = EncryptDecryptApp(root)
    root.mainloop()

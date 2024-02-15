# Encrypt and Decrypt Files using DES Encryption Algorithm

This Python script allows users to encrypt and decrypt files using the Data Encryption Standard (DES) encryption algorithm. DES is a symmetric-key block cipher that operates on 64-bit blocks of plaintext at a time. This script provides options to generate and save encryption keys, as well as to read keys from files for encryption and decryption operations.

## Features

- File encryption using DES algorithm
- File decryption using DES algorithm
- Generation and saving of DES encryption keys
- Reading DES encryption keys from files
- User-friendly graphical interface for file selection

## Prerequisites

- Python 3.x
- `PyCryptoDome` library for DES encryption (`pip install pycryptodome`)
- `Tkinter` library for GUI file dialogs (usually included in Python standard library)

## Usage

1. Clone this repository or download the `encrypt_decrypt_des.py` script.
2. Ensure you have the necessary prerequisites installed.
3. Run the script using Python:

    ```
    python encrypt_decrypt_des.py
    ```

4. Follow the on-screen instructions to perform encryption or decryption operations on files.
5. You can choose to generate a new encryption key or read an existing key from a file.

## Example

Here's how you can use the script:

1. Run the script.
2. Choose an option from the menu:
    - File Encrypt
    - Decrypt
    - Generate and Save Key
    - Read Key from File
    - Exit

3. Follow the prompts to select input and output files, as well as whether to generate a new encryption key or use an existing one.
4. The encrypted or decrypted file will be saved accordingly.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or create a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

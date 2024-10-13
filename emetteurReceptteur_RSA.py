import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64  # To encode and decode binary data

# Function to generate RSA keys
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)

    messagebox.showinfo("Keys Generated", "Keys saved as private.pem and public.pem")

# Function to encrypt a message
def encrypt_message():
    message = message_entry.get()
    if not message:
        messagebox.showwarning("Input Error", "Please enter a message to encrypt.")
        return

    try:
        with open("public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())

        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message.encode('utf-8'))

        # Encode the encrypted message in base64 for safe handling
        encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')
        encrypted_message.set(encrypted_base64)

        messagebox.showinfo("Encryption Successful", "Message encrypted!")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

# Function to decrypt a message
def decrypt_message():
    encrypted_base64 = encrypted_message.get()
    if not encrypted_base64:
        messagebox.showwarning("Input Error", "Please encrypt a message first.")
        return

    try:
        with open("private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())

        # Decode the encrypted message from base64 back to binary
        encrypted = base64.b64decode(encrypted_base64)

        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted).decode('utf-8')

        decrypted_message.set(decrypted)
        messagebox.showinfo("Decryption Successful", "Message decrypted!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# GUI setup
root = tk.Tk()
root.title("RSA Encryption/Decryption")
root.geometry("600x400")

# Variables to hold encrypted and decrypted messages
encrypted_message = tk.StringVar()
decrypted_message = tk.StringVar()

# Layout
tk.Label(root, text="Message to Encrypt:", font=("Arial", 12)).pack(pady=10)
message_entry = tk.Entry(root, width=50, font=("Arial", 12))
message_entry.pack(pady=5)

tk.Button(root, text="Generate Keys", command=generate_keys, font=("Arial", 12)).pack(pady=10)
tk.Button(root, text="Encrypt Message", command=encrypt_message, font=("Arial", 12)).pack(pady=10)
tk.Button(root, text="Decrypt Message", command=decrypt_message, font=("Arial", 12)).pack(pady=10)

tk.Label(root, text="Encrypted Message (Base64):", font=("Arial", 12)).pack(pady=10)
tk.Entry(root, textvariable=encrypted_message, width=50, font=("Arial", 12)).pack(pady=5)

tk.Label(root, text="Decrypted Message:", font=("Arial", 12)).pack(pady=10)
tk.Entry(root, textvariable=decrypted_message, width=50, font=("Arial", 12)).pack(pady=5)

# Start the GUI event loop
root.mainloop()

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class ImageEncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Image Encryption Tool")

        self.image_label = tk.Label(self.master)
        self.image_label.pack()

        self.upload_button = tk.Button(self.master, text="Upload Image", command=self.upload_image)
        self.upload_button.pack(pady=10)

        self.key_label = tk.Label(self.master, text="Encryption Key (16 characters):")
        self.key_label.pack()
        self.key_entry = tk.Entry(self.master, show='*')
        self.key_entry.pack()

        self.encrypt_button = tk.Button(self.master, text="Encrypt Image", command=self.encrypt_image)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(self.master, text="Decrypt Image", command=self.decrypt_image)
        self.decrypt_button.pack(pady=5)

        self.feedback_label = tk.Label(self.master, text="")
        self.feedback_label.pack()

    def upload_image(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.image = Image.open(file_path)
            self.display_image(self.image)

    def display_image(self, image):
        image.thumbnail((300, 300))
        photo = ImageTk.PhotoImage(image)
        self.image_label.configure(image=photo)
        self.image_label.image = photo

    def encrypt_image(self):
        key = self.key_entry.get()
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be 16 characters long.")
            return

        try:
            # Prepare the cipher
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=backend)
            encryptor = cipher.encryptor()

            # Prepare the data
            plaintext = np.array(self.image)
            plaintext_bytes = plaintext.tobytes()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            plaintext_padded = padder.update(plaintext_bytes) + padder.finalize()

            # Encrypt the data
            ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
            encrypted_image = Image.frombytes(self.image.mode, self.image.size, ciphertext[:len(plaintext_bytes)])
            self.display_image(encrypted_image)
            self.encrypted_bytes = ciphertext
            self.feedback_label.config(text="Image encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_image(self):
        key = self.key_entry.get()
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be 16 characters long.")
            return

        try:
            # Prepare the cipher
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()

            # Decrypt the data
            ciphertext = self.encrypted_bytes
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext_bytes = unpadder.update(plaintext_padded) + unpadder.finalize()

            # Convert bytes back to image
            plaintext = np.frombuffer(plaintext_bytes, dtype=np.uint8).reshape(self.image.size[1], self.image.size[0],
                                                                               -1)
            decrypted_image = Image.fromarray(plaintext, self.image.mode)
            self.display_image(decrypted_image)
            self.feedback_label.config(text="Image decrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


def main():
    root = tk.Tk()
    app = ImageEncryptionApp(root)
    #GUI Window Title
    root.title("Image Encryption using AES")
    #provide size to window
    root.geometry("450x450")
    
    root.mainloop()



if __name__ == "__main__":
    main()

import tkinter as tk
from tkinter import messagebox

class TextEncryptorDecryptor:
    def __init__(self, master):
        self.master = master
        master.title("Text Encryptor and Decryptor")
        master.geometry("400x250")
        master.resizable(False, False)
        master.configure(bg="#f0f0f0")

        self.label = tk.Label(master, text="Enter text:", bg="#f0f0f0", fg="#333333", font=("Arial", 12))
        self.label.pack()

        self.text_entry = tk.Entry(master, width=40, font=("Arial", 12))
        self.text_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt, bg="#4CAF50", fg="white", font=("Arial", 12))
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt, bg="#FF5733", fg="white", font=("Arial", 12))
        self.decrypt_button.pack()

        self.result_entry = tk.Entry(master, width=40, font=("Arial", 12))
        self.result_entry.pack(pady=10)

        self.copy_button = tk.Button(master, text="Copy", command=self.copy_to_clipboard, bg="#3498db", fg="white", font=("Arial", 12))
        self.copy_button.pack()

        self.secret_alphabet = {'a': 'Th4@', 'b': '3@@', 'c': '&@)', 'd': 'Ju3', 'e': 'u(@.',
                                'f': '*hd', 'g': '*jK', 'h': '_+', 'i': 'lf"', 'j': 'Ni$',
                                'k': '1~8jA', 'l': '(d)', 'm': 'fjJ', 'n': 'UJ', 'o': 'gG13',
                                'p': '7Y??', 'q': '1(00', 'r': '94!', 's': '1*%', 't': 'AA01',
                                'u': '-)8', 'v': '4jX', '@37y': 'T/:', 'x': '!6(', 'y': '=_y}',
                                'z': '8Uiy', '0': 'g0G', '1': 'tI2#', '2': 'j|8', '3': ')3s',
                                '4': 'P;r@', '5': '*/.', '6': 'L}a', '7': '+@d', '8': '_pE',
                                '9': 'Hu8'}

        self.reverse_secret_alphabet = {v: k for k, v in self.secret_alphabet.items()}

    def encrypt(self):
        plaintext = self.text_entry.get().lower()
        encrypted_text = ''
        for char in plaintext:
            if char in self.secret_alphabet:
                encrypted_text += self.secret_alphabet[char] + ' '
            else:
                encrypted_text += char
        self.result_entry.delete(0, tk.END)
        self.result_entry.insert(tk.END, encrypted_text)

    def decrypt(self):
        encrypted_text = self.text_entry.get().split()
        decrypted_text = ''
        for char in encrypted_text:
            if char in self.reverse_secret_alphabet:
                decrypted_text += self.reverse_secret_alphabet[char]
            else:
                decrypted_text += char
        self.result_entry.delete(0, tk.END)
        self.result_entry.insert(tk.END, decrypted_text)

    def copy_to_clipboard(self):
        result_text = self.result_entry.get()
        self.master.clipboard_clear()
        self.master.clipboard_append(result_text)
        messagebox.showinfo("Copied", "Text copied to clipboard!")

def main():
    root = tk.Tk()
    app = TextEncryptorDecryptor(root)
    root.mainloop()

if __name__ == "__main__":
    main()

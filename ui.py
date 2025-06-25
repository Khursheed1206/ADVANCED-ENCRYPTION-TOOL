import tkinter as tk
from tkinter import filedialog, messagebox
from encryption import encrypt_file, decrypt_file

def run_app():
    def encrypt():
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        password = entry.get()
        output_path = filepath + ".enc"
        try:
            encrypt_file(filepath, password, output_path)
            messagebox.showinfo("Success", f"Encrypted to {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt():
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        password = entry.get()

        if filepath.lower().endswith(".enc"):
            output_path = filepath[:-4]
        else:
            output_path = filepath + ".decrypted"

        try:
            decrypt_file(filepath, password, output_path)
            messagebox.showinfo("Success", f"Decrypted file saved to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

    root = tk.Tk()
    root.title("Advanced Encryption Tool")

    tk.Label(root, text="Password:").pack(pady=5)
    entry = tk.Entry(root, show='*', width=40)
    entry.pack()

    tk.Button(root, text="Encrypt File", command=encrypt).pack(pady=10)
    tk.Button(root, text="Decrypt File", command=decrypt).pack(pady=5)

    root.mainloop()

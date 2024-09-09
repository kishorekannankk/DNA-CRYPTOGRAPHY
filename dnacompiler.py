import tkinter as tk
from tkinter import messagebox

# DNA to Binary mapping and Binary to DNA mapping
dna_to_binary_mapping = {
    'A': '00',  # Adenine
    'C': '10',  # Cytosine
    'G': '01',  # Guanine
    'T': '11'   # Thymine
}
binary_to_dna_mapping = {v: k for k, v in dna_to_binary_mapping.items()}

# Binary to DNA and DNA to Binary for text encryption
binary_to_dna_encrypt = {
    '00': 'A',
    '01': 'T',
    '10': 'C',
    '11': 'G'
}
dna_to_binary_encrypt = {v: k for k, v in binary_to_dna_encrypt.items()}

# Function to convert DNA sequence to binary (converter)
def dna_to_bin(dna_sequence):
    try:
        binary_sequence = ''.join([dna_to_binary_mapping[base] for base in dna_sequence])
        return binary_sequence
    except KeyError:
        raise ValueError("Invalid DNA sequence. Please enter valid characters (A, C, G, T).")

# Function to convert binary sequence to DNA (converter)
def bin_to_dna(binary_sequence):
    try:
        dna_sequence = ''.join([binary_to_dna_mapping[binary_sequence[i:i+2]] for i in range(0, len(binary_sequence), 2)])
        return dna_sequence
    except KeyError:
        raise ValueError("Invalid binary sequence. Please enter a valid binary string (00, 01, 10, 11).")
    except IndexError:
        raise ValueError("Binary sequence must be in multiples of 2 bits (00, 01, 10, 11).")

# Function to convert text to binary (string converter)
def string_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

# Function to convert integer to binary (integer converter)
def integer_to_binary(integer_value):
    try:
        return format(int(integer_value), '08b')
    except ValueError:
        raise ValueError("Invalid integer. Please enter a valid number.")

# Convert binary to DNA sequence (encryption)
def binary_to_dna_sequence(binary_data):
    return ''.join(binary_to_dna_encrypt[binary_data[i:i+2]] for i in range(0, len(binary_data), 2))

# Convert DNA sequence back to binary (decryption)
def dna_to_binary_sequence(dna_sequence):
    return ''.join(dna_to_binary_encrypt[nucleotide] for nucleotide in dna_sequence)

# Convert binary to text (decryption)
def binary_to_text(binary_data):
    return ''.join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))

# Encrypt message into DNA sequence
def encrypt_message(message):
    binary_data = string_to_binary(message)
    dna_sequence = binary_to_dna_sequence(binary_data)
    return dna_sequence

# Decrypt DNA sequence back to message
def decrypt_message(dna_sequence):
    binary_data = dna_to_binary_sequence(dna_sequence)
    message = binary_to_text(binary_data)
    return message

# GUI functions
def binary_to_dna():
    binary_sequence = entry_input.get().strip()
    if len(binary_sequence) % 2 != 0:
        messagebox.showerror("Error", "Binary sequence must be a multiple of 2 bits.")
        return
    try:
        result = bin_to_dna(binary_sequence)
        result_label.config(text=f"DNA Sequence: {result}")
        copy_result = result
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def dna_to_binary():
    dna_sequence = entry_input.get().strip().upper()
    if any(base not in 'ACGT' for base in dna_sequence):
        messagebox.showerror("Error", "Please enter a valid DNA sequence (A, C, G, T).")
        return
    try:
        result = dna_to_bin(dna_sequence)
        result_label.config(text=f"Binary Sequence: {result}")
        copy_result = result
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def handle_encrypt():
    message = encrypt_entry.get()
    if not message:
        messagebox.showerror("Input Error", "Please enter a message to encrypt.")
        return
    encrypted_dna = encrypt_message(message)
    encrypt_result_label.config(text=f"Encrypted DNA Sequence: {encrypted_dna}")
    copy_button_encrypt.config(state=tk.NORMAL)

def handle_decrypt():
    dna_sequence = decrypt_entry.get()
    if not dna_sequence:
        messagebox.showerror("Input Error", "Please enter a DNA sequence to decrypt.")
        return
    try:
        decrypted_message = decrypt_message(dna_sequence)
        decrypt_result_label.config(text=f"Decrypted Message: {decrypted_message}")
    except:
        messagebox.showerror("Decryption Error", "Invalid DNA sequence!")

def string_to_binary_converter():
    text = string_entry.get().strip()
    if not text:
        messagebox.showerror("Input Error", "Please enter a string to convert.")
        return
    binary = string_to_binary(text)
    string_result_label.config(text=f"Binary of String: {binary}")
    copy_button_string.config(state=tk.NORMAL)

def integer_to_binary_converter():
    integer_value = integer_entry.get().strip()
    try:
        binary = integer_to_binary(integer_value)
        integer_result_label.config(text=f"Binary of Integer: {binary}")
        copy_button_integer.config(state=tk.NORMAL)
    except ValueError as e:
        messagebox.showerror("Error", str(e))

# Copy functions for all results
def copy_to_clipboard(result_label):
    result = result_label.cget("text").split(": ")[1]
    if result:
        root.clipboard_clear()
        root.clipboard_append(result)
        messagebox.showinfo("Copied", "Result copied to clipboard!")

# Set up the UI window
root = tk.Tk()
root.title("DNA Encryption & Binary-DNA Converter")

# Conversion Section (Binary to DNA and DNA to Binary)
tk.Label(root, text="Enter Binary or DNA Sequence:").grid(row=0, column=0, padx=10, pady=10)
entry_input = tk.Entry(root, width=50)
entry_input.grid(row=0, column=1, padx=10, pady=10)

binary_to_dna_button = tk.Button(root, text="Convert Binary to DNA", command=binary_to_dna)
binary_to_dna_button.grid(row=1, column=0, padx=10, pady=10)

dna_to_binary_button = tk.Button(root, text="Convert DNA to Binary", command=dna_to_binary)
dna_to_binary_button.grid(row=1, column=1, padx=10, pady=10)

result_label = tk.Label(root, text="Result: ", font=("Arial", 14))
result_label.grid(row=2, column=0, columnspan=2, padx=10, pady=20)

copy_button_result = tk.Button(root, text="Copy Result", command=lambda: copy_to_clipboard(result_label), state=tk.DISABLED)
copy_button_result.grid(row=2, column=2, padx=10, pady=10)

# Encryption Section
tk.Label(root, text="Enter Message to Encrypt:").grid(row=3, column=0, padx=10, pady=10)
encrypt_entry = tk.Entry(root, width=50)
encrypt_entry.grid(row=3, column=1, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Encrypt", command=handle_encrypt)
encrypt_button.grid(row=4, column=0, padx=10, pady=10)

encrypt_result_label = tk.Label(root, text="")
encrypt_result_label.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

copy_button_encrypt = tk.Button(root, text="Copy Encrypted DNA", command=lambda: copy_to_clipboard(encrypt_result_label), state=tk.DISABLED)
copy_button_encrypt.grid(row=5, column=2, padx=10, pady=10)

# Decryption Section
tk.Label(root, text="Enter DNA Sequence to Decrypt:").grid(row=6, column=0, padx=10, pady=10)
decrypt_entry = tk.Entry(root, width=50)
decrypt_entry.grid(row=6, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=handle_decrypt)
decrypt_button.grid(row=7, column=0, padx=10, pady=10)

decrypt_result_label = tk.Label(root, text="")
decrypt_result_label.grid(row=8, column=0, columnspan=2, padx=10, pady=10)

copy_button_decrypt = tk.Button(root, text="Copy Decrypted Message", command=lambda: copy_to_clipboard(decrypt_result_label), state=tk.DISABLED)
copy_button_decrypt.grid(row=8, column=2, padx=10, pady=10)

# String to Binary Converter
tk.Label(root, text="Enter String to Convert to Binary:").grid(row=9, column=0, padx=10, pady=10)
string_entry = tk.Entry(root, width=50)
string_entry.grid(row=9, column=1, padx=10, pady=10)

string_button = tk.Button(root, text="Convert String to Binary", command=string_to_binary_converter)
string_button.grid(row=10, column=0, padx=10, pady=10)

string_result_label = tk.Label(root, text="")
string_result_label.grid(row=11, column=0, columnspan=2, padx=10, pady=10)

copy_button_string = tk.Button(root, text="Copy String Binary", command=lambda: copy_to_clipboard(string_result_label), state=tk.DISABLED)
copy_button_string.grid(row=11, column=2, padx=10, pady=10)

# Integer to Binary Converter
tk.Label(root, text="Enter Integer to Convert to Binary:").grid(row=12, column=0, padx=10, pady=10)
integer_entry = tk.Entry(root, width=50)
integer_entry.grid(row=12, column=1, padx=10, pady=10)

integer_button = tk.Button(root, text="Convert Integer to Binary", command=integer_to_binary_converter)
integer_button.grid(row=13, column=0, padx=10, pady=10)

integer_result_label = tk.Label(root, text="")
integer_result_label.grid(row=14, column=0, columnspan=2, padx=10, pady=10)

copy_button_integer = tk.Button(root, text="Copy Integer Binary", command=lambda: copy_to_clipboard(integer_result_label), state=tk.DISABLED)
copy_button_integer.grid(row=14, column=2, padx=10, pady=10)

# Start the Tkinter event loop
root.mainloop()

import re

def is_valid_username(username):
  # Check if username is valid (contains only letters, numbers and underscores)
  return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

def is_valid_password(password):
  has_number = re.search(r'[0-9]', password)
  has_symbol = re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
  has_character = re.search(r'[A-Z]', password)
  return has_number, has_character and has_symbol


def vigenere_encrypt(text, key, encrypt=True):
    if not key:
        raise ValueError("Key cannot be empty")
    
    result = []
    key_index = 0
    
    # Konversi key menjadi nilai numerik (0-255)
    key_values = [ord(k) % 256 for k in key]
    key_length = len(key_values)
    
    for char in text:
        # Dapatkan nilai kunci saat ini
        key_value = key_values[key_index % key_length]
        
        # Jika karakter adalah huruf, enkripsi dengan metode substitusi
        if char.isalpha():
            # Tentukan basis (97 untuk huruf kecil, 65 untuk huruf besar)
            base = 97 if char.islower() else 65
            # Konversi ke angka (0-25), lakukan shift, kemudian kembali ke huruf
            char_num = ord(char) - base
            if encrypt:
                new_num = (char_num + key_value) % 26
            else:
                new_num = (char_num - key_value) % 26
            result.append(chr(base + new_num))
        else:
            # Untuk karakter non-huruf, biarkan tidak berubah
            result.append(char)
        
        # Selalu increment key_index untuk menggunakan seluruh key
        key_index += 1
    
    return ''.join(result)

def vigenere_decrypt(text, key, decrypt=True):
    return vigenere_encrypt(text, key, encrypt=False)

def vigenere_encrypt_biner(file_content, key):
    if not key:
        raise ValueError("Key cannot be empty")
    
    key_bytes = bytes(key, 'utf-8')
    key_length = len(key_bytes)
    
    encrypted = bytearray()
    for i in range(len(file_content)):
        # Gunakan modulo untuk mengulang key
        key_byte = key_bytes[i % key_length]
        encrypted.append(file_content[i] ^ key_byte)
    
    return bytes(encrypted)

def vigenere_decrypt_biner(file_content, key):
    return vigenere_encrypt_biner(file_content, key)
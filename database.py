from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin
import mysql.connector
import base64
import os

ENCRYPTION_KEY = base64.b64decode('fbmSy9zxu44WS1T5qp0eNg==')

# Fungsi untuk membuat koneksi ke database
def get_db_connection():
    connection = mysql.connector.connect(
        host="127.0.0.1",     # Host MySQL (XAMPP)
        user="root",          # Username MySQL
        password="",          # Password MySQL (kosong jika default)
        database="user_database"  # Nama database
    )
    return connection

def encrypt_data(data: str, encryption_key: bytes) -> str:
    if not isinstance(data, str):
        raise TypeError("Data must be a string")
    
    # Generate a random 16-byte IV (AES block size)
    iv = os.urandom(16)
    
    # Create AES cipher instance
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Create padder
    padder = padding.PKCS7(128).padder()
    
    # Convert string to bytes and pad
    data_bytes = data.encode('utf-8')
    padded_data = padder.update(data_bytes) + padder.finalize()
    
    # Encrypt padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Encode both the encrypted data and IV in base64
    encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    
    return f"{iv_b64}:{encrypted_b64}"
    
def decrypt_data(encrypted_string: str, encryption_key: bytes) -> str:
    try:
        if not encrypted_string:
            return ""
        
        # Split IV and encrypted data
        iv_b64, encrypted_b64 = encrypted_string.split(':')
        
        # Decode base64
        iv = base64.b64decode(iv_b64)
        encrypted_data = base64.b64decode(encrypted_b64)
        
        # Create cipher instance
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Create unpadder
        unpadder = padding.PKCS7(128).unpadder()
        
        # Decrypt data
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        # Convert bytes back to string
        return decrypted_data.decode('utf-8')
    
    except Exception as e:
        print(f"Error during decryption: {e}")
        return ""

# Fungsi untuk menambahkan data ke tabel `users`
def add_user(full_name, username, hashed_password):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        query = "INSERT INTO users (full_name, username, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (full_name, username, hashed_password))
        connection.commit()
        return True  # Mengembalikan jumlah baris yang terpengaruh
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return True
    finally:
        cursor.close()
        connection.close()
        
def get_user(username):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)  # Hasil query dalam bentuk dictionary
    try:
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()  
        print(f"Password hash retrieved from DB: {result['password']}")
        if result:
            return User(
                result['id'], 
                result['full_name'], 
                result['username'], 
                result['password'], 
                result['failed_attempts'], 
                result['locked_until']
            )
        return None
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None
    finally:
        cursor.close()
        connection.close()
        
        
def get_user_by_id(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()  # Hasil query dalam bentuk dictionary
    try:
        query = "SELECT * FROM users WHERE id = %s"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        if result:
            return User(result[0], result[1], result[2], result[3])
        return None
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None
    finally:
        cursor.close()
        connection.close()
        
def get_history_by_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        query = """
            SELECT id, Content_Preview, Method, Status, Result, timestamp, Content_Type 
            FROM User_History 
            WHERE user_id = %s 
            ORDER BY timestamp DESC
        """
        cursor.execute(query, (user_id,))
        result = cursor.fetchall()

        # Dekripsi data setelah diambil dari database
        for item in result:
            try:
                if item['Content_Preview']:
                    item['Content_Preview'] = decrypt_data(item['Content_Preview'], ENCRYPTION_KEY)
                if item['Method']:
                    item['Method'] = decrypt_data(item['Method'], ENCRYPTION_KEY)
                if item['Result']:
                    item['Result'] = decrypt_data(item['Result'], ENCRYPTION_KEY)
            except Exception as e:
                print(f"Decryption error for item {item}: {e}")

        print("Decrypted Result:", result)
        return result
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []
    finally:
        cursor.close()
        connection.close()

        
def add_history_by_user(user_id, Content_Preview, Method, Status, Result, Content_Type):
    # Lakukan hashing pada data yang sensitif
    encrypted_content_preview = encrypt_data(Content_Preview, ENCRYPTION_KEY) 
    encrypted_method = encrypt_data(Method, ENCRYPTION_KEY) 
    encrypted_result = encrypt_data(Result, ENCRYPTION_KEY) 
    
    # Data lainnya tetap disimpan tanpa perubahan
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        query = """
            INSERT INTO User_History
            (user_id, Content_Preview, Method, Status, Result, Content_Type) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            user_id, 
            encrypted_content_preview, 
            encrypted_method, 
            Status, 
            encrypted_result, 
            Content_Type
        ))
        connection.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False
    finally:
        cursor.close()
        connection.close()
        
class User(UserMixin):
    def __init__(self, id, full_name, username, password, failed_attempts=0, locked_until=None):
        self.id = id
        self.full_name = full_name
        self.username = username
        self.password = password
        self.failed_attempts = failed_attempts
        self.locked_until = locked_until
        self.is_active = True
        
    def is_active(self):
        return self.is_active
    
    def is_active(self, value):
        self.is_active = value
        
        

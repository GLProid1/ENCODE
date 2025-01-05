from Crypto.Cipher import AES
from PIL import Image
from Crypto.Util.Padding import pad, unpad
import base64


# Fungsi mengenkripsi data menggunakan AES
def aes_encrypt(data, key):
  try:
    # Decode the base64 key first
    key_bytes = base64.b64decode(key)
    
    # Validasi panjang kunci
    if len(key_bytes) not in [16, 24, 32]:
      raise ValueError(f"Invalid key length: {len(key)} bytes. Must be 16, 24, or 32 bytes.")
    
    # Inisiasi cipher AES
    cipher = AES.new(key_bytes, AES.MODE_CBC) # Mode CBC digunakan disini
    iv = cipher.iv # iv (Initialization vektor)
    
    encrypt_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    
    return base64.b64encode(iv + encrypt_data).decode('utf-8') # Gabungkan IV dengan ciphertext
  except Exception as e:
    raise ValueError(f"Encryption failed: {str(e)}")

# Fungsi mendekripsi data menggunakna AES
def aes_decrypt(encrypt_data,key):
  try:
    # Decode the base64 key first
    key_bytes = base64.b64decode(key)
    
    if len(key_bytes) not in [16, 24, 32]:
      raise ValueError(f"Invalid key length: {len(key)} bytes. Must be 16, 24, or 32 bytes.")
    
    encrypt_data = base64.b64decode(encrypt_data)
    
    # Ambil IV dan ciphertext
    if len(encrypt_data) < 16 + AES.block_size:
      raise ValueError("Invalid ciphertext length!")
    
    iv = encrypt_data[:16] # Ambil IV awal pada ciphertext
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    
    # Dekripsi dan hapus padding
    decrypt_data = unpad(cipher.decrypt(encrypt_data[16:]), AES.block_size)
    return decrypt_data.decode('utf-8')
  except Exception as e:
    raise ValueError(f"Decryption failed: {str(e)}")

# Fungsi untuk menyisipkan pesan ke gambar
def encode_image(image_path, encrypt_message, output_path):
  try:
    with Image.open(image_path) as img:
      img = img.convert("RGB")
      width, height = img.size
      pixels = img.load()
    
      # Ubah pesan menjadi biner
      binary_message = ''.join(format(ord(c), '08b') for c in encrypt_message)
      binary_message += '1111111111111110' # Penanda akhir pesan
    
      max_capacity = width * height
      if len(binary_message) > max_capacity:
        raise ValueError("Message is too long to fit in the image!")
    
      # sisipkan pesan ke dalam pixel gambar
      data_index = 0
      for y in range(height):
        for x in range(width):
          if data_index < len(binary_message):
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(binary_message[data_index]) #Ubah bit LSB
            pixels[x, y] = (r, g, b)
            data_index += 1
          else:
            break
      img.save(output_path)
  except Exception as e:
    raise ValueError (f"Failed to encode image: {str(e)}")
        
# Fungsi untuk membaca pesan dari gambar
def decode_image(image_path):
  try:
    with Image.open(image_path) as img:
      img = img.convert("RGB")
      pixels = img.load()
      width, height = img.size
    
      # Baca image dari bit
      binary_message = ""
      for y in range(height):
        for x in range(width):
          r, g, b = pixels[x, y]
          binary_message += str(r & 1)
          
          if len(binary_message) >= 16:
            delimiter_pos = binary_message.find('1111111111111110')
            if delimiter_pos != -1:
              binary_message = binary_message[:delimiter_pos]

              if len(binary_message) % 8 != 0:
                raise ValueError("Decode binary message length is not a multiple of 8!")

              message = ""
              for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:
                  message += chr(int(byte, 2))
                  
              return message
      raise ValueError("No message found in the image")
  except Exception as e:
    raise ValueError (f"Failed to decode image: {str(e)}")
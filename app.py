from database import add_user, get_user, get_user_by_id, get_history_by_user, add_history_by_user, get_db_connection
from vigenere import vigenere_encrypt, vigenere_decrypt, is_valid_password, is_valid_username, vigenere_encrypt_biner, vigenere_decrypt_biner
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from steganografi import aes_encrypt, aes_decrypt, decode_image, encode_image
from werkzeug.security import check_password_hash, generate_password_hash
from file_handler import read_file_content, write_file_content
from login_manager import EnhancedLoginManager
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from mimetypes import guess_type
from io import BytesIO
import mysql.connector
import mimetypes
import base64
import secrets
import os

app = Flask(__name__)
login_manager = EnhancedLoginManager(app)
app.config['SECRET_KEY'] = 'Akusukaayam12%'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCODED_FOLDER'] = 'encoded_images'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCODED_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)  # Menggunakan fungsi dari database.py
    
@app.route('/')
def dashboard():
  return render_template("dashboard.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('Home'))

    if request.method == 'POST':
        username = request.form.get('Username')
        password = request.form.get('Password')


        if not username or not password:
            flash('Please fill in all fields', 'error')
            print(f"Input password: {password}")
            return render_template('login.html', user=current_user)

        # Fetch user from the database
        user = get_user(username)

        if user:
            # Use EnhancedLoginManager to validate login
            success, message = login_manager.authorize_login(user, password)

            if success:
                # Login successful
                connection = get_db_connection()
                cursor = connection.cursor()
                try:
                    # Reset failed_attempts and locked_until
                    query = "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s"
                    cursor.execute(query, (user.id,))
                    connection.commit()

                    login_user(user)
                    session['full_name'] = user.full_name
                    session['login_fresh'] = datetime.now().isoformat()  # Mark login as fresh
                    flash(message, 'success')
                    return redirect(url_for('Home'))
                finally:
                    cursor.close()
                    connection.close()
            else:
                # Login failed
                connection = get_db_connection()
                cursor = connection.cursor()
                try:
                    # Update failed_attempts and locked_until
                    query = "UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s"
                    cursor.execute(query, (user.failed_attempts, user.locked_until, user.id))
                    connection.commit()
                finally:
                    cursor.close()
                    connection.close()

                flash(message, 'error')
        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html', user=current_user)


@app.route('/sign-up', methods=['GET', 'POST'])
def register():
    
    if current_user.is_authenticated:
        return redirect(url_for('Home'))
    
    if request.method == 'POST':
        full_name = request.form.get('Full Name')
        username = request.form.get('Username')
        password = request.form.get('Password')

        # Check apakah semua field terisi
        if not full_name or not username or not password:
            flash("All fields are required!", 'error')
            return redirect('/sign-up')

        if len(username) < 4:
            flash('Username must be at least 4 characters long', 'error')
        elif not is_valid_username(username):
            flash('Username can only contain letters, numbers, and underscores.', 'error')
        elif len(full_name) < 2:
            flash('First name must be at least 2 characters long!', 'error')
        elif not is_valid_password(password):
            flash('Password must contain at least one number and one special character!', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters long!', 'error')
        elif username == password :
            flash('Username and password cannot be the same!', 'error')
        else:
            hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
            result = add_user(full_name, username, hashed_password)
            if result:
                flash('Account created successfully!', 'success')
                return redirect(url_for('Home'))
            else:
                flash('Failed to create account. Please try again.', 'error')

    return render_template('register.html', user=current_user, is_home_page=False)

@app.route('/Home')
@login_required
def Home():
    full_name = session.get('full_name', 'Guest')
    return render_template('home.html', full_name=full_name, is_home_page=True, user=current_user)

@app.route('/Encrypt&Decrypt', methods=['GET', 'POST'])
@login_required
def Encrypt_Decrypt():
    if request.method == "POST":
        # Periksa jenis konten
        if request.content_type == "application/json":
            # Enkripsi/Dekripsi teks
            data = request.json
            action = data.get("action")
            key = data.get("key")
            text = data.get("text")

            if not key or len(key) < 1 :
                return jsonify({"error": "Key must be alphabetic!"}), 400

            if action == "encrypt":
                result = vigenere_encrypt(text, key)
                add_history_by_user(
                    user_id=current_user.id,
                    Content_Preview=text[:50],
                    Result=result,
                    Method="Vigenere Text",
                    Status="Encrypted",
                    Content_Type="Text",
                )
            elif action == "decrypt":
                result = vigenere_decrypt(text, key)
                add_history_by_user(
                    user_id=current_user.id,
                    Content_Preview=text[:50],
                    Result=result,
                    Method="Vigenere Text",
                    Status="Decrypted",
                    Content_Type="Text"
                )
            else:
                return flash("Invalid action!", "error")

            return jsonify({"result": result})

        elif "multipart/form-data" in request.content_type:
            # Enkripsi/Dekripsi file
            action = request.form.get("action")
            key = request.form.get("key")
            file = request.files.get("file")

            if not key or len(key) < 1 :
                return flash("Key must not be empty!", "error")
            if not file or file.filename == "":
                return flash("No file selected!", "error")

            # Ambil nama file dan ekstensi nya
            filename = file.filename
            name, ext = os.path.splitext(filename)
            ext = ext.lower()
            
            # Validasi ekstensi file
            allowed_extensions = [".txt", ".pdf", ".docx", ".doc", ".csv", ".xlsx", ".sql"]
            if ext not in allowed_extensions:
                return jsonify({"error": f"Unsupported file type: {ext}"}), 400
            
            try:
                file_content = read_file_content(file, ext)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
            
            # Enkripsi atau dekripsi file biner
            if action == "encrypt":
                result = vigenere_encrypt_biner(file_content, key)
                encrypted_filename = f"encrypt_{name}{ext}"
                add_history_by_user(
                    user_id=current_user.id,
                    Content_Preview=filename,
                    Result=encrypted_filename,
                    Method="Vigenere File",
                    Status="Encrypted",
                    Content_Type="File"
                )
                output = BytesIO()
                output.write(result)
                output.seek(0)
                return send_file(output, download_name=encrypted_filename, as_attachment=True)
            
            elif action == "decrypt":
                if not filename.startswith("encrypt_"):
                    return jsonify ({"error": "File is not encrypted!"}), 400
                try:
                    result = vigenere_decrypt_biner(file_content, key)
                except Exception as e:
                    return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

                # Mengembalikan ekstensi file asli
                decrypted_filename = filename[len("encrypt_") :]
                
                add_history_by_user(
                    user_id=current_user.id,
                    Content_Preview=filename[len("encrypt_") :],
                    Result=decrypted_filename,
                    Method="Vigenere File",
                    Status="Decrypted",
                    Content_Type="File"
                )
                output = BytesIO()
                output.write(result)
                output.seek(0)
                return send_file(output, download_name=decrypted_filename, as_attachment=True)
            else:
                return jsonify({"error": "Invalid action!"}), 400
        else:
            return jsonify({"error": "Unsupported content type!"}), 400

    # Render default page untuk GET requests
    return render_template("encrypt.html", is_home_page=False, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/history', methods=['GET', 'POST'])
@login_required
def history():
    # Ambil parameter halaman dari url
    page = request.args.get('page', 1, type=int)
    items_per_page = 5
    offset = (page - 1) * items_per_page

    # Ambil data user history yang sudah didekripsi
    user_history = get_history_by_user(current_user.id)

    # Pagination manual
    total_items = len(user_history)
    total_pages = (total_items + items_per_page - 1) // items_per_page
    paginated_history = user_history[offset:offset + items_per_page]

    return render_template(
        'history.html', 
        user=current_user, 
        history=paginated_history,
        page=page,
        total_pages=total_pages,
        total_items=total_items,
        items_per_page=items_per_page
    )

        
@app.route('/delete/<int:history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        query = "DELETE FROM User_History WHERE id = %s AND user_id = %s"
        cursor.execute(query, (history_id, current_user.id,))
        connection.commit()
        flash("History deleted successfully.", "success")
    except mysql.connector.Error as err:
        flash(f"Error deleting history: {err}", "error")
    finally:
        cursor.close()
        connection.close()
    return redirect(url_for('history'))
        
        
def allowed_file(file):
    mime_type, _ = guess_type(file.filename)
    app.logger.info(f"Detected MIME type: {mime_type}")
    return mime_type in ['image/png', 'image/bmp']

@app.route('/Steganografi', methods=['GET','POST'])
@login_required
def steganografi():
    if request.method == "POST":
        action = request.form.get('action') # Menentukan encrypt atau decrypt
        file = request.files.get('file')
        key = request.form.get('key')
        secret_message = request.form.get('secret_message', '') # Untuk encrypt
        app.logger.info(f"Received secret message: {secret_message}")

        # Validasi file
        if not file or not allowed_file(file):
            flash("Please upload a valid image file (PNG, BMP)!", "error")
            return redirect(url_for('steganografi'))
        
        if not file.content_length and file.content_length > 10 * 1024 * 1024: # Error jika file lebih besar dari 10 MB
            flash("File size exceeds 10 MB limits!", "error")
            return redirect(url_for('steganografi'))

        if not key:
            flash("Encryption key is required!", "error")
            return redirect(url_for('steganografi'))
        
        try:
            key_bytes = base64.b64decode(key)
            if len(key_bytes) not in [16, 24, 32]:
                flash("Invalid encryption key length: {len(key_bytes)} bytes. Must be 16, 24, 32 bytes", "error")
                return redirect(url_for('steganografi'))
        except Exception as e:
            flash("Invalid base64 key format", "error")
            return redirect(url_for('steganografi'))
    
        # Simpan gambar sementara
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            if action == 'encrypt':
                if not secret_message:
                    flash("Please enter a secret message to encrypt!", "error")
                    return redirect(url_for('steganografi'))
                
                # Encrypt Message
                encrypt_message = aes_encrypt(secret_message, key.encode('utf-8'))
                output_path = os.path.join(app.config['ENCODED_FOLDER'], f"encoded_{filename}")
                encode_image(file_path, encrypt_message, output_path)
                add_history_by_user(
                    user_id=current_user.id,
                    Content_Preview=filename,
                    Result=output_path,
                    Method="Steganography",
                    Status="Encrypted",
                    Content_Type="Image"
                )
                return send_file(output_path, as_attachment=True)
            
            elif action == 'decrypt':
                try:
                    decoded_message = decode_image(file_path)
                    decrypted_message = aes_decrypt(decoded_message, key.encode('utf-8'))
                    add_history_by_user(
                        user_id=current_user.id,
                        Content_Preview=file.filename,
                        Result=decrypted_message,
                        Method="Steganography",
                        Status="Decrypted",
                        Content_Type="Image"
                    )
                    return jsonify({"decrypted_message": decrypted_message})
                except Exception as e:
                    return jsonify({"error": str(e)}), 400
            else:
                flash("Invalid action!", "error")
        
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
                
    return render_template('steganografi.html', is_home_page=False, user=current_user)

@app.route('/generate_key', methods=['GET'])
@login_required
def generate_key():
    try:
        # Ambil parameter bit dari permintaan
        aes_bit = request.args.get('bit', default='128', type=int)
        
        # Validasi nilai AES bit
        valid_bits = {
            128: 16,  # 16 bytes = 128 bits
            192: 24,  # 24 bytes = 192 bits
            256: 32   # 32 bytes = 256 bits
        }
        
        if aes_bit not in valid_bits:
            return jsonify({'error': 'Invalid AES bit selection'}), 400
            
        # Generate kunci dengan panjang yang sesuai
        key_length = valid_bits[aes_bit]
        key = secrets.token_bytes(key_length)
        
        # Verifikasi panjang key
        if len(key) != key_length:
            raise ValueError(f"Generated key length ({len(key)}) does not match required length ({key_length})")
            
        # Encode key dalam base64
        base64_key = base64.b64encode(key).decode('utf-8')
        
        # Log untuk debugging (opsional)
        print(f"Generated key length: {len(key)} bytes")
        print(f"Base64 key length: {len(base64_key)} characters")
        
        return jsonify({
            'base64_key': base64_key,
            'key_length': len(key),
            'bit_size': aes_bit
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/Digital Signature')
@login_required
def digital_signature():
    return render_template('digital_signature.html', user=current_user)

if __name__ == '__main__':  
    app.run(debug=True)

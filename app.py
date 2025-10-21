import os
import time
from flask import Flask, render_template, request, send_from_directory, url_for

# (Keep your existing Crypto imports)
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16) 
app.config['UPLOAD_FOLDER'] = 'uploads' # Set the folder for uploads

# (Keep your existing constants and get_key_from_password function)
SALT_SIZE = 16
KEY_SIZES = {'AES': 16, 'DES': 8, 'RC4': 16}
IV_SIZES = {'AES': 16, 'DES': 8}

def get_key_from_password(password, salt, algorithm):
    key_size = KEY_SIZES.get(algorithm)
    if not key_size:
        raise ValueError("Invalid algorithm specified for key derivation")
    return PBKDF2(password, salt, dkLen=key_size)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    # --- Get form data (same as before) ---
    file = request.files.get('file')
    password = request.form.get('password')
    algorithm = request.form.get('algorithm')
    if not all([file, password, algorithm]):
        return "Missing file, password, or algorithm", 400
    
    file_data = file.read()
    
    # --- Performance Measurement Start ---
    start_time = time.perf_counter()

    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt, algorithm)
    # (Encryption logic is the same as before)
    if algorithm in ['AES', 'DES']:
        iv = get_random_bytes(IV_SIZES[algorithm])
        CipherClass = AES if algorithm == 'AES' else DES
        cipher = CipherClass.new(key, CipherClass.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(file_data, CipherClass.block_size))
        final_data = salt + iv + encrypted_data
    elif algorithm == 'RC4':
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(file_data)
        final_data = salt + encrypted_data
    else:
        return "Invalid algorithm", 400

    # --- Performance Measurement End ---
    end_time = time.perf_counter()
    
    # --- Collect Metrics ---
    metrics = {
        'operation': 'Encryption',
        'algorithm': algorithm,
        'time': end_time - start_time,
        'size': len(final_data) # Ciphertext size
    }
    
    # --- Save file and render results ---
    output_filename = f"encrypted_{file.filename}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as f_out:
        f_out.write(final_data)
        
    return render_template('results.html', metrics=metrics, filename=output_filename)


@app.route('/decrypt', methods=['POST'])
def decrypt():
    # --- Get form data (same as before) ---
    file = request.files.get('file')
    password = request.form.get('password')
    algorithm = request.form.get('algorithm')
    if not all([file, password, algorithm]):
        return "Missing file, password, or algorithm", 400
    
    encrypted_data_with_salt = file.read()

    # --- Performance Measurement Start ---
    start_time = time.perf_counter()

    try:
        # (Decryption logic is the same as before)
        salt = encrypted_data_with_salt[:SALT_SIZE]
        key = get_key_from_password(password, salt, algorithm)
        if algorithm in ['AES', 'DES']:
            iv_size = IV_SIZES[algorithm]
            iv = encrypted_data_with_salt[SALT_SIZE : SALT_SIZE + iv_size]
            ciphertext = encrypted_data_with_salt[SALT_SIZE + iv_size:]
            CipherClass = AES if algorithm == 'AES' else DES
            cipher = CipherClass.new(key, CipherClass.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(ciphertext), CipherClass.block_size)
        elif algorithm == 'RC4':
            ciphertext = encrypted_data_with_salt[SALT_SIZE:]
            cipher = ARC4.new(key)
            decrypted_data = cipher.encrypt(ciphertext)
        else:
            return "Invalid algorithm", 400
    except (ValueError, KeyError):
        return "Decryption failed. Please check your key, algorithm, and file.", 400

    # --- Performance Measurement End ---
    end_time = time.perf_counter()

    # --- Collect Metrics ---
    metrics = {
        'operation': 'Decryption',
        'algorithm': algorithm,
        'time': end_time - start_time,
        'size': len(decrypted_data) # Original file size
    }

    # --- Save file and render results ---
    output_filename = f"decrypted_{file.filename}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted_data)
        
    return render_template('results.html', metrics=metrics, filename=output_filename)


# --- Add a new route for downloading files ---
@app.route('/download/<path:filename>')
def download_file(filename):
    """Serves files from the UPLOAD_FOLDER."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


if __name__ == '__main__':
    # Ensure the upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
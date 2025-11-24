import os
import time
import uuid
import csv
import threading
import datetime
import json
import io
import openpyxl
from flask import (
    Flask, render_template, request, send_from_directory,
    url_for, redirect, flash, abort, session, jsonify, send_file,
    after_this_request
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # --- ADDED THIS IMPORT ---
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import key_store
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "You must be logged in to access this page."

# --- Constants (Unchanged) ---
SALT_SIZE = 16
KEY_SIZES = {'AES': 16, 'DES': 8, 'RC4': 16}
IV_SIZES = {'AES': 16, 'DES': 8}
REPORT_PREFIX = 'REPORT_'

# --- Helper Functions (Unchanged) ---
def get_key_from_password(password, salt, algorithm):
    key_size = KEY_SIZES.get(algorithm)
    if not key_size:
        raise ValueError("Invalid algorithm specified for key derivation")
    return PBKDF2(password, salt, dkLen=key_size)

PERFORMANCE_LOG_FILE = 'performance_log.csv'
LOG_HEADERS = [
    'timestamp', 'user_id', 'username', 'operation', 'algorithm',
    'execution_time_s', 'output_size_bytes', 'original_filename'
]
log_lock = threading.Lock()

def log_performance(log_data):
    with log_lock:
        file_exists = os.path.exists(PERFORMANCE_LOG_FILE)
        with open(PERFORMANCE_LOG_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=LOG_HEADERS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(log_data)

def parse_excel(file_stream):
    data = []
    workbook = openpyxl.load_workbook(file_stream, read_only=True)
    sheet = workbook.active
    if not sheet: return []
    headers = [cell.value for cell in sheet[1]]
    for row in sheet.iter_rows(min_row=2, values_only=True):
        if all(cell is None for cell in row): continue
        if any(cell is not None for cell in row):
            data.append(dict(zip(headers, row)))
    return data

# --- Database Models ---

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    requester = db.relationship('User', foreign_keys=[requester_id], backref=db.backref('sent_friend_requests', lazy='dynamic'))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_friend_requests', lazy='dynamic'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), default='consultant', nullable=False)
    files = db.relationship('SecureFile', backref='owner', lazy='dynamic')
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def get_friends(self):
        approved_sent = Friendship.query.filter_by(requester_id=self.id, status='approved').all()
        approved_received = Friendship.query.filter_by(receiver_id=self.id, status='approved').all()
        friends = []
        for req in approved_sent: friends.append(req.receiver)
        for req in approved_received: friends.append(req.requester)
        return friends
    def get_friend_ids(self):
        friend_ids = set()
        approved_sent = Friendship.query.filter_by(requester_id=self.id, status='approved').all()
        for req in approved_sent: friend_ids.add(req.receiver_id)
        approved_received = Friendship.query.filter_by(receiver_id=self.id, status='approved').all()
        for req in approved_received: friend_ids.add(req.requester_id)
        return list(friend_ids)
    def get_friend_status(self, other_user):
        request = Friendship.query.filter(or_((Friendship.requester_id == self.id) & (Friendship.receiver_id == other_user.id), (Friendship.requester_id == other_user.id) & (Friendship.receiver_id == self.id))).first()
        if not request: return 'none'
        return request.status

class SecureFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    algorithm_used = db.Column(db.String(10), nullable=False)
    upload_timestamp = db.Column(db.DateTime, server_default=db.func.now())
    # --- POINT 2: Replaced 'encrypted_data' with 'storage_filename' ---
    storage_filename = db.Column(db.String(255), nullable=False, unique=True)
    # encrypted_data = db.Column(db.LargeBinary, nullable=False) # --- REMOVED ---
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=True, nullable=False)

class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), default='pending', nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('secure_file.id'), nullable=False)
    
    # --- NEW: The Digital Envelope ---
    encrypted_sym_key = db.Column(db.LargeBinary, nullable=True) 
    # ---------------------------------
    
    requester = db.relationship('User', backref='requests_made', lazy='joined')
    file = db.relationship('SecureFile', backref='requests_received', lazy='joined')

class ParsedReportData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('secure_file.id'), unique=True, nullable=False)
    encrypted_json_data = db.Column(db.LargeBinary, nullable=False)
    file = db.relationship('SecureFile', backref=db.backref('parsed_data', uselist=False))

# --- === NEW NOTIFICATION TABLE (FIXED) === ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True) # Its own primary key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Who gets the notification
    text = db.Column(db.String(255), nullable=False)
    # --- NEW: Foreign keys to link to the *actual* request ---
    related_friend_request_id = db.Column(db.Integer, db.ForeignKey('friendship.id', ondelete='SET NULL'), nullable=True)
    related_file_request_id = db.Column(db.Integer, db.ForeignKey('access_request.id', ondelete='SET NULL'), nullable=True)
    
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    
    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic'))
    friend_request = db.relationship('Friendship', foreign_keys=[related_friend_request_id])
    file_request = db.relationship('AccessRequest', foreign_keys=[related_file_request_id])


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Auth Routes (Unchanged) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role') # Get the role from the form
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))
            
        # --- 1. Generate RSA Key Pair (The "Mailbox") ---
        key = RSA.generate(2048)
        
        # --- 2. Export Public Key (Open to everyone) ---
        public_key_pem = key.publickey().export_key().decode('utf-8')
        
        # --- 3. Export Private Key (Encrypted with User's Password) ---
        # We use the user's login password to lock this key. 
        # Even WE (the admins) cannot read this key without their password.
        encrypted_private_key = key.export_key(
            passphrase=password, 
            pkcs=8, 
            protection="scryptAndAES128-CBC"
        )
        
        # --- 4. Create User in SQL (Public Info) ---
        new_user = User(username=username, role=role, public_key=public_key_pem)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit() # Commit now to generate the user.id
        
        # --- 5. Store Private Key in NoSQL (Hidden Info) ---
        key_store.store_private_key(new_user.id, encrypted_private_key)
        
        flash('Account created! Keys generated and secured.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgotpassword.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# --- Core App Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    owned_files = SecureFile.query.filter_by(user_id=current_user.id).order_by(SecureFile.upload_timestamp.desc()).all()
    approved_requests = AccessRequest.query.filter_by(requester_id=current_user.id, status='approved').all()
    shared_files = [req.file for req in approved_requests if req.file]
    public_files = SecureFile.query.filter(SecureFile.is_public == True, SecureFile.user_id != current_user.id).order_by(SecureFile.upload_timestamp.desc()).all()
    friend_ids = current_user.get_friend_ids()
    friends_files = []
    if friend_ids:
        friends_files = SecureFile.query.filter(SecureFile.is_public == False, SecureFile.user_id.in_(friend_ids)).order_by(SecureFile.upload_timestamp.desc()).all()
    your_requests = AccessRequest.query.filter_by(requester_id=current_user.id).all()
    request_status_map = {req.file_id: req.status for req in your_requests}
    return render_template('dashboard.html',
                           owned_files=owned_files,
                           shared_files=shared_files,
                           public_files=public_files,
                           friends_files=friends_files,
                           request_status_map=request_status_map,
                           report_prefix=REPORT_PREFIX
                           )

@app.route('/users')
@login_required
def find_users():
    all_users = User.query.filter(User.id != current_user.id).all()
    return render_template('users.html', all_users=all_users)

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    file = request.files.get('file')
    password = request.form.get('password')
    algorithm = request.form.get('algorithm')
    visibility = request.form.get('visibility')
    
    if not file: return jsonify({'success': False, 'error': 'No file selected'}), 400
    if not all([password, algorithm, visibility]): return jsonify({'success': False, 'error': 'Missing password, algorithm, or visibility setting'}), 400

    is_public = (visibility == 'public')
    
    # --- MODIFIED: Secure the filename immediately ---
    original_filename = secure_filename(file.filename)
    if not original_filename:
         return jsonify({'success': False, 'error': 'Invalid file name'}), 400
    # --- END MODIFIED ---
    _, ext = os.path.splitext(original_filename)
    file_data = file.read()
    
    start_time = time.perf_counter()
    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt, algorithm)
    
    iv = None 
    CipherClass = None
    cipher_obj = None
    
    # --- POINT 2: Generate a unique storage name ---
    storage_name = f"{uuid.uuid4().hex}{ext}"
    
    if algorithm in ['AES', 'DES']:
        iv = get_random_bytes(IV_SIZES[algorithm])
        CipherClass = AES if algorithm == 'AES' else DES
        cipher_obj = CipherClass.new(key, CipherClass.MODE_CBC, iv)
        encrypted_data = cipher_obj.encrypt(pad(file_data, CipherClass.block_size))
        final_data = salt + iv + encrypted_data
    elif algorithm == 'RC4':
        cipher_obj = ARC4.new(key)
        encrypted_data = cipher_obj.encrypt(file_data)
        final_data = salt + encrypted_data
    else: return jsonify({'success': False, 'error': 'Invalid algorithm'}), 400
    
    end_time = time.perf_counter()
    metrics = { 'operation': 'Encryption', 'algorithm': algorithm, 'time': end_time - start_time, 'size': len(final_data) }
    
    # --- NEW: Save encrypted file to 'uploads' folder ---
    try:
        # --- POINT 2: Save to 'uploads/' with the unique storage_name ---
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
        with open(save_path, 'wb') as f:
            f.write(final_data)
    except Exception as e:
        # Log the error but don't fail the whole operation,
        # as the file is still saved in the DB.
        print(f"Error saving encrypted file to disk: {e}")
    # --- END NEW ---
    
    new_file_record = SecureFile(
        original_filename=original_filename,
        algorithm_used=algorithm,
        user_id=current_user.id,
        # --- POINT 2: Save the unique name to the DB, not the data ---
        storage_filename=storage_name,
        # encrypted_data=final_data, # --- REMOVED ---
        is_public=is_public
    )
    db.session.add(new_file_record)
    db.session.commit()

    if original_filename.startswith(REPORT_PREFIX):
        try:
            file_stream = io.BytesIO(file_data)
            parsed_data = parse_excel(file_stream)
            if parsed_data:
                json_data = json.dumps(parsed_data).encode('utf-8')
                if algorithm in ['AES', 'DES']:
                    cipher_json = CipherClass.new(key, CipherClass.MODE_CBC, iv) 
                    encrypted_json = cipher_json.encrypt(pad(json_data, CipherClass.block_size))
                else:
                    cipher_json = ARC4.new(key)
                    encrypted_json = cipher_json.encrypt(json_data)
                new_report = ParsedReportData(
                    file_id=new_file_record.id,
                    encrypted_json_data=encrypted_json
                )
                db.session.add(new_report)
                db.session.commit()
        except Exception as e:
            print(f"ERROR parsing Excel file {original_filename}: {e}")

    log_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'user_id': current_user.id, 'username': current_user.username,
        'operation': metrics['operation'], 'algorithm': metrics['algorithm'],
        'execution_time_s': metrics['time'], 'output_size_bytes': metrics['size'],
        'original_filename': original_filename
    }
    threading.Thread(target=log_performance, args=(log_data,)).start()
    
    return jsonify({'success': True, 'metrics': metrics})

@app.route('/decrypt/<int:file_id>', methods=['POST'])
@login_required
def decrypt(file_id):
    file_record = SecureFile.query.get_or_404(file_id)
    
    # 1. Determine who is asking (Owner vs Consultant)
    is_owner = file_record.user_id == current_user.id
    access_request = AccessRequest.query.filter_by(
        requester_id=current_user.id,
        file_id=file_record.id,
        status='approved'
    ).first()

    if not is_owner and not access_request:
        return jsonify({'success': False, 'error': 'Permission denied'}), 403

    # The user enters a password in the UI
    input_password = request.form.get('password')
    if not input_password:
        return jsonify({'success': False, 'error': 'Password is required'}), 400

    algorithm = file_record.algorithm_used
    final_file_password = None

    # --- BRANCH A: OWNER (Classic Mode) ---
    if is_owner:
        # The owner knows the file password directly
        final_file_password = input_password

    # --- BRANCH B: CONSULTANT (Asymmetric Mode) ---
    else:
        # 1. The input is actually their LOGIN password. Use it to unlock their Private Key.
        try:
            # Retrieve encrypted private key from NoSQL
            encrypted_priv_key = key_store.get_private_key(current_user.id)
            if not encrypted_priv_key:
                return jsonify({'success': False, 'error': 'No private key found for your account.'}), 400
            
            # Unlock the Private Key
            priv_key_obj = RSA.import_key(encrypted_priv_key, passphrase=input_password)
            cipher_rsa = PKCS1_OAEP.new(priv_key_obj)
            
            # 2. Use Private Key to decrypt the shared File Password (The "Digital Envelope")
            if not access_request.encrypted_sym_key:
                 return jsonify({'success': False, 'error': 'No key shared for this file.'}), 400
                 
            decrypted_bytes = cipher_rsa.decrypt(access_request.encrypted_sym_key)
            final_file_password = decrypted_bytes.decode('utf-8')
            
        except ValueError:
             return jsonify({'success': False, 'error': 'Wrong Login Password (could not unlock private key).'}), 400
        except Exception as e:
             return jsonify({'success': False, 'error': f'Key decryption failed: {str(e)}'}), 500

    # --- COMMON PATH: Actual File Decryption ---
    # Now that we have 'final_file_password' (either directly or via RSA), we proceed.
    
    storage_name = file_record.storage_filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'error': 'File not found on server.'}), 404
        
    try:
        with open(file_path, 'rb') as f:
            encrypted_data_with_salt = f.read()
    except Exception as e:
        return jsonify({'success': False, 'error': 'Could not read file.'}), 500
    
    decrypted_data = None
    start_time = time.perf_counter()
    
    try:
        salt = encrypted_data_with_salt[:SALT_SIZE]
        # Generate the symmetric key using the recovered password
        key = get_key_from_password(final_file_password, salt, algorithm)
        
        if algorithm in ['AES', 'DES']:
            iv_size = IV_SIZES[algorithm]
            iv = encrypted_data_with_salt[SALT_SIZE: SALT_SIZE + iv_size]
            ciphertext = encrypted_data_with_salt[SALT_SIZE + iv_size:]
            CipherClass = AES if algorithm == 'AES' else DES
            cipher = CipherClass.new(key, CipherClass.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(ciphertext), CipherClass.block_size)
        elif algorithm == 'RC4':
            ciphertext = encrypted_data_with_salt[SALT_SIZE:]
            cipher = ARC4.new(key)
            decrypted_data = cipher.encrypt(ciphertext)
            
    except (ValueError, KeyError):
        return jsonify({'success': False, 'error': 'Decryption failed. Wrong password or corrupted file.'}), 400
    
    end_time = time.perf_counter()
    metrics = { 'operation': 'Decryption', 'algorithm': algorithm, 'time': end_time - start_time, 'size': len(decrypted_data) }

    # (Logging code omitted for brevity, but you can keep your logging logic here)

    temp_filename = f"{uuid.uuid4().hex}.tmp"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted_data)
        
    return jsonify({
        'success': True,
        'metrics': metrics,
        'temp_file': temp_filename,
        'original_name': file_record.original_filename
    })

@app.route('/view_report/<int:file_id>', methods=['GET', 'POST'])
@login_required
def view_report(file_id):
    file_record = SecureFile.query.get_or_404(file_id)
    report_data = file_record.parsed_data
    if not report_data:
        flash('No parsed report data found for this file.', 'error')
        return redirect(url_for('dashboard'))

    # 1. Determine Access
    is_owner = file_record.user_id == current_user.id
    access_request = AccessRequest.query.filter_by(
        requester_id=current_user.id, 
        file_id=file_record.id, 
        status='approved'
    ).first()
    
    if not is_owner and not access_request:
        flash('You do not have permission to view this report.', 'error')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        input_password = request.form.get('password')
        
        if not input_password:
            flash('Password is required.', 'error')
            return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)
            
        algorithm = file_record.algorithm_used
        final_file_password = None
        
        # --- BRANCH A: OWNER (Direct Access) ---
        if is_owner:
            final_file_password = input_password
            
        # --- BRANCH B: CONSULTANT (RSA Unlock) ---
        else:
            try:
                encrypted_priv_key = key_store.get_private_key(current_user.id)
                if not encrypted_priv_key:
                     flash('No private key found for your account.', 'error')
                     return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)

                # Unlock Private Key with Login Password
                priv_key_obj = RSA.import_key(encrypted_priv_key, passphrase=input_password)
                cipher_rsa = PKCS1_OAEP.new(priv_key_obj)
                
                if not access_request.encrypted_sym_key:
                     flash('No shared key found for this file.', 'error')
                     return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)
                
                # Decrypt the shared key
                decrypted_bytes = cipher_rsa.decrypt(access_request.encrypted_sym_key)
                final_file_password = decrypted_bytes.decode('utf-8')

            except ValueError:
                 flash('Wrong Login Password (could not unlock private key).', 'error')
                 return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)
            except Exception as e:
                 flash(f'Key decryption failed: {str(e)}', 'error')
                 return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)

        # --- COMMON PATH: Decrypting the Report ---
        try:
            # We assume we need to re-derive the key from the password + salt 
            # (Note: For this to work, we need the SALT. 
            # In your original code, you read the salt from the encrypted *file*.
            # But here, we only have the report blob.
            # FIX: We will grab the salt from the physical file header to be safe.)
            
            storage_name = file_record.storage_filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
            
            with open(file_path, 'rb') as f:
                encrypted_file_header = f.read(SALT_SIZE) # Just read the salt
            
            salt = encrypted_file_header # The salt is the first 16 bytes
            key = get_key_from_password(final_file_password, salt, algorithm)
            
            decrypted_json_data = None
            if algorithm in ['AES', 'DES']:
                CipherClass = AES if algorithm == 'AES' else DES
                # Note: We need a fresh IV for the JSON blob. 
                # In your original encrypt code: cipher_json = CipherClass.new(key, CipherClass.MODE_CBC, iv)
                # You reused the IV from the file encryption.
                # We need to read that IV from the file header too.
                iv_size = IV_SIZES[algorithm]
                with open(file_path, 'rb') as f:
                    f.seek(SALT_SIZE)
                    iv = f.read(iv_size)
                
                cipher = CipherClass.new(key, CipherClass.MODE_CBC, iv)
                decrypted_json_data = unpad(cipher.decrypt(report_data.encrypted_json_data), CipherClass.block_size)
            elif algorithm == 'RC4':
                cipher = ARC4.new(key)
                decrypted_json_data = cipher.encrypt(report_data.encrypted_json_data)
                
            parsed_data = json.loads(decrypted_json_data.decode('utf-8'))
            if not parsed_data:
                flash('Report data was empty.', 'info')
                return render_template('view_data.html', file=file_record, headers=None, data=[], is_owner=is_owner)
                
            headers = parsed_data[0].keys()
            return render_template('view_data.html', file=file_record, headers=headers, data=parsed_data, is_owner=is_owner)
            
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            flash(f'Decryption failed. Please check your password. {e}', 'error')
            return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)

    # GET Request
    return render_template('view_data.html', file=file_record, headers=None, data=None, is_owner=is_owner)

@app.route('/download_temp/<path:temp_filename>')
@login_required
def download_temp_file(temp_filename):
    if '..' in temp_filename or os.path.isabs(temp_filename):
        abort(400)
    original_name = request.args.get('filename', 'decrypted_file')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    
    @after_this_request
    def remove_temp_file(response):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error removing temp file {temp_filename}: {e}")
        return response

    return send_file(
        file_path,
        download_name=original_name,
        as_attachment=True
    )

# --- === REWIRED API ROUTES === ---

@app.route('/api/friend_action/<int:user_id>', methods=['POST'])
@login_required
def friend_action(user_id):
    user_to_action = User.query.get_or_404(user_id)
    if user_to_action.id == current_user.id: return jsonify({'success': False, 'error': 'Cannot action yourself'}), 400
    action = request.json.get('action')
    existing_request = Friendship.query.filter(or_((Friendship.requester_id == current_user.id) & (Friendship.receiver_id == user_to_action.id), (Friendship.requester_id == user_to_action.id) & (Friendship.receiver_id == current_user.id))).first()

    if action == 'request':
        if existing_request: return jsonify({'success': False, 'error': 'Request already pending or user is already a friend.'}), 400
        new_request = Friendship(requester_id=current_user.id, receiver_id=user_to_action.id, status='pending')
        db.session.add(new_request)
        db.session.commit() # Commit to get the ID
        
        # Create notification for the receiver
        notif_text = f"<strong>{current_user.username}</strong> sent you a friend request."
        new_notif = Notification(user_id=user_to_action.id, text=notif_text, is_read=False, related_friend_request_id=new_request.id)
        db.session.add(new_notif)
        
        db.session.commit()
        flash(f"Friend request sent to {user_to_action.username}.", "success")
        return jsonify({'success': True, 'new_status': 'pending'})

    if not existing_request: return jsonify({'success': False, 'error': 'No friendship record found.'}), 404

    if action == 'cancel':
        if existing_request.status == 'pending' and existing_request.requester_id == current_user.id:
            # Delete the notification *first*
            Notification.query.filter_by(related_friend_request_id=existing_request.id).delete()
            db.session.delete(existing_request)
            db.session.commit()
            flash("Friend request canceled.", "info")
            return jsonify({'success': True, 'new_status': 'none'})
        else: return jsonify({'success': False, 'error': 'Cannot cancel this request.'}), 403

    if action == 'remove':
        if existing_request.status == 'approved':
            notif_text = f"<strong>{current_user.username}</strong> removed you as a friend."
            new_notif = Notification(user_id=user_to_action.id, text=notif_text, is_read=False)
            db.session.add(new_notif)
            
            db.session.delete(existing_request)
            db.session.commit()
            flash(f"Removed {user_to_action.username} from friends.", "success")
            return jsonify({'success': True, 'new_status': 'none'})
        else: return jsonify({'success': False, 'error': 'Cannot remove a non-friend.'}), 403
            
    return jsonify({'success': False, 'error': 'Invalid action.'}), 400

@app.route('/api/get_new_notifications')
@login_required
def api_get_new_notifications():
    """
    Fetches all *unread* notifications for the current user.
    """
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).order_by(Notification.timestamp.desc()).all()
    
    notif_list = [
        {'id': n.id, 'text': n.text} for n in notifications
    ]
    
    return jsonify({
        'new_notification_count': len(notif_list),
        'notifications': notif_list
    })
    
# --- REWRITTEN: /api/get_notification_history (For Modal) ---
@app.route('/api/get_notification_history')
@login_required
def api_get_notification_history():
    """
    Fetches ALL notifications (read and unread) for the modal.
    """
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.timestamp.desc()).limit(20).all() # Get last 20
    
    notif_list = []
    unread_ids = []
    for n in notifications:
        notif_type = 'system' # Default (e.g., "request denied")
        request_id = None
        # Check if this is an *actionable* request
        if n.related_friend_request_id and n.friend_request and n.friend_request.status == 'pending':
            notif_type = 'friend_request'
            request_id = n.related_friend_request_id
        elif n.related_file_request_id and n.file_request and n.file_request.status == 'pending':
            notif_type = 'file_request'
            request_id = n.related_file_request_id
            
        notif_list.append({
            'id': n.id,
            'text': n.text, 
            'is_read': n.is_read,
            'type': notif_type,
            'request_id': request_id # Pass the *actual* request ID (or None)
        })
        if not n.is_read:
            unread_ids.append(n.id)

    # Mark all fetched notifications as read
    if unread_ids:
        Notification.query.filter(Notification.id.in_(unread_ids)).update({'is_read': True}, synchronize_session=False)
        db.session.commit()
    
    return jsonify({'notifications': notif_list})


# --- REWIRED: /api/respond_friend_request ---
@app.route('/api/respond_friend_request/<int:request_id>', methods=['POST'])
@login_required
def api_respond_friend(request_id):
    action = request.json.get('action')
    if action not in ['approve', 'deny']: return jsonify({'success': False, 'error': 'Invalid action'}), 400
    
    # The ID from the modal is the Friendship ID
    friend_request = Friendship.query.get(request_id)
    
    if not friend_request or friend_request.receiver_id != current_user.id:
         return jsonify({'success': False, 'error': 'Request not found or not authorized'}), 404

    # Mark the associated notification as read
    Notification.query.filter_by(related_friend_request_id=request_id, user_id=current_user.id).update({'is_read': True})
    
    if action == 'approve':
        friend_request.status = 'approved'
        notif_text = f"<strong>{current_user.username}</strong> approved your friend request."
        new_notif = Notification(user_id=friend_request.requester_id, text=notif_text, is_read=False)
        db.session.add(new_notif)
    else: # 'deny'
        notif_text = f"<strong>{current_user.username}</strong> denied your friend request."
        new_notif = Notification(user_id=friend_request.requester_id, text=notif_text, is_read=False)
        db.session.add(new_notif)
        # --- POINT 3: Standardize deny logic ---
        friend_request.status = 'denied'
        # db.session.delete(friend_request) # --- REMOVED ---
        
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/respond_file_request/<int:request_id>', methods=['POST'])
@login_required
def api_respond_file(request_id):
    action = request.json.get('action')
    # --- NEW: Capture the password sent from the frontend ---
    file_password = request.json.get('file_password') 
    
    if action not in ['approve', 'deny']: 
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    
    access_request = AccessRequest.query.get(request_id)
    if not access_request or access_request.file.owner.id != current_user.id:
         return jsonify({'success': False, 'error': 'Request not found or not authorized'}), 404

    # Mark notification as read
    Notification.query.filter_by(related_file_request_id=request_id, user_id=current_user.id).update({'is_read': True})
        
    if action == 'approve':
        # --- NEW SECURITY CHECK ---
        if not file_password:
             return jsonify({'success': False, 'error': 'Password required to approve access.'}), 400
             
        try:
            # 1. Get the Consultant's Public Key (The "Mailbox")
            requester_key_pem = access_request.requester.public_key
            if not requester_key_pem:
                return jsonify({'success': False, 'error': 'Requester has no public key!'}), 400
            
            # 2. Prepare the Asymmetric Cipher
            recipient_key = RSA.import_key(requester_key_pem)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            
            # 3. Encrypt the File Password
            # We encode it to bytes, then encrypt it
            enc_key = cipher_rsa.encrypt(file_password.encode('utf-8'))
            
            # 4. Store the "Digital Envelope"
            access_request.encrypted_sym_key = enc_key
            access_request.status = 'approved'
            
            # Notify the consultant
            notif_text = f"Access <strong>approved</strong> for <strong>{access_request.file.original_filename}</strong>."
            new_notif = Notification(user_id=access_request.requester_id, text=notif_text, is_read=False)
            db.session.add(new_notif)
            
        except Exception as e:
            return jsonify({'success': False, 'error': f'Encryption handshake failed: {str(e)}'}), 500

    else: # 'deny'
        access_request.status = 'denied'
        notif_text = f"Access <strong>denied</strong> for <strong>{access_request.file.original_filename}</strong>."
        new_notif = Notification(user_id=access_request.requester_id, text=notif_text, is_read=False)
        db.session.add(new_notif)
        
    db.session.commit()
    return jsonify({'success': True})

# --- REWIRED: /api/request_file_access ---
@app.route('/api/request_file_access/<int:file_id>', methods=['POST'])
@login_required
def api_request_file_access(file_id):
    file_to_request = SecureFile.query.get_or_404(file_id)
    if file_to_request.user_id == current_user.id: return jsonify({'success': False, 'error': 'You own this file'}), 400
    
    existing_request = AccessRequest.query.filter_by(requester_id=current_user.id, file_id=file_id).first()
    if existing_request: return jsonify({'success': False, 'error': 'Request already sent', 'status': existing_request.status}), 400
        
    new_request = AccessRequest(
        requester_id=current_user.id,
        file_id=file_id,
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit() # Commit to get new_request.id
    
    # Create notification for the file owner
    notif_text = f"<strong>{current_user.username}</strong> requested access to <strong>{file_to_request.original_filename}</strong>."
    new_notif = Notification(user_id=file_to_request.user_id, text=notif_text, is_read=False, related_file_request_id=new_request.id)
    db.session.add(new_notif)
    
    db.session.commit()
    return jsonify({'success': True, 'status': 'pending'})

# --- === NEW "MARK AS READ" API === ---
@app.route('/api/mark_read', methods=['POST'])
@login_required
def mark_read():
    notif_id = request.json.get('id')
    if not notif_id:
        return jsonify({'success': False, 'error': 'Missing notification ID'}), 400
        
    notification = Notification.query.get(notif_id)
    
    if not notification or notification.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Not authorized'}), 403
        
    notification.is_read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = SecureFile.query.get_or_404(file_id)
    if file_record.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Not authorized'}), 403

    # --- POINT 2: Also delete the file from the 'uploads' folder ---
    try:
        storage_name = file_record.storage_filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        # Log the error but don't stop the DB deletion
        print(f"Error deleting file {file_path} from disk: {e}")
    # --- End of new block ---

    # Delete associated parsed report data if exists
    if file_record.parsed_data:
        db.session.delete(file_record.parsed_data)

    # Delete associated access requests
    AccessRequest.query.filter_by(file_id=file_id).delete()

    # Delete associated notifications
    Notification.query.filter_by(related_file_request_id=file_id).delete()
    Notification.query.filter_by(related_friend_request_id=file_id).delete()

    db.session.delete(file_record)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/download_encrypted/<int:file_id>')
@login_required
def download_encrypted(file_id):
    file_record = SecureFile.query.get_or_404(file_id)
    
    storage_name = file_record.storage_filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_name)
    
    if not os.path.exists(file_path):
        flash('File not found on server storage.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    # --- MODIFIED LINE ---
    # Send the file with its *original* name, not with .enc
    download_name = file_record.original_filename
    
    return send_file(
        file_path,
        download_name=download_name,
        as_attachment=True
    )

# --- Main ---
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
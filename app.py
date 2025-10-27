import os
import time
import uuid
import csv
import threading
import datetime
from flask import Flask, render_template, request, send_from_directory, url_for, redirect, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Crypto imports
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# --- App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Extension Setup ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "You must be logged in to access this page."

SALT_SIZE = 16
KEY_SIZES = {'AES': 16, 'DES': 8, 'RC4': 16}
IV_SIZES = {'AES': 16, 'DES': 8}


def get_key_from_password(password, salt, algorithm):
    key_size = KEY_SIZES.get(algorithm)
    if not key_size:
        raise ValueError("Invalid algorithm specified for key derivation")
    return PBKDF2(password, salt, dkLen=key_size)


PERFORMANCE_LOG_FILE = 'performance_log.csv'
LOG_HEADERS = ['timestamp', 'user_id', 'username', 'operation', 'algorithm', 'execution_time_s', 'output_size_bytes',
               'original_filename']
log_lock = threading.Lock()


def log_performance(log_data):
    """
    Appends a new row to the performance CSV file in a thread-safe way.
    """
    with log_lock:
        file_exists = os.path.exists(PERFORMANCE_LOG_FILE)

        with open(PERFORMANCE_LOG_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=LOG_HEADERS)

            if not file_exists:
                writer.writeheader()  # header if needed

            writer.writerow(log_data)


# --- Database Models ---

# NEW: Association Table for Many-to-Many sharing
file_shares = db.Table('file_shares',
                       db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                       db.Column('file_id', db.Integer, db.ForeignKey('secure_file.id'), primary_key=True)
                       )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # file owner
    files = db.relationship('SecureFile', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class SecureFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    algorithm_used = db.Column(db.String(10), nullable=False)
    upload_timestamp = db.Column(db.DateTime, server_default=db.func.now())
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    # OWNER
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # NEW: Relationship to see who this file is shared with
    # many-to-many
    users_shared_with = db.relationship('User', secondary=file_shares,
                                        lazy='dynamic',
                                        backref=db.backref('files_shared_with_me', lazy='dynamic'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Auth Routes  ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/forgot_password')
def forgot_password():
    """A static page for the 'forgot password' link."""
    return render_template('forgotpassword.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# --- Core App Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    # UPDATED: We now fetch two separate lists
    # 1. Files the user OWNS
    owned_files = SecureFile.query.filter_by(user_id=current_user.id).order_by(SecureFile.upload_timestamp.desc()).all()
    # 2. Files SHARED WITH the user
    shared_files = current_user.files_shared_with_me.order_by(SecureFile.upload_timestamp.desc()).all()

    return render_template('dashboard.html', owned_files=owned_files, shared_files=shared_files)


@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    # --- Get form data ---
    file = request.files.get('file')
    password = request.form.get('password')
    algorithm = request.form.get('algorithm')
    if not all([file, password, algorithm]):
        flash('Missing file, password, or algorithm', 'error')
        return redirect(url_for('dashboard'))

    file_data = file.read()
    start_time = time.perf_counter()
    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt, algorithm)

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
        flash('Invalid algorithm', 'error')
        return redirect(url_for('dashboard'))

    end_time = time.perf_counter()
    metrics = {
        'operation': 'Encryption',
        'algorithm': algorithm,
        'time': end_time - start_time,
        'size': len(final_data)
    }

    original_filename = file.filename
    stored_filename = f"{uuid.uuid4().hex}.enc"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)

    with open(output_path, 'wb') as f_out:
        f_out.write(final_data)

    new_file_record = SecureFile(
        original_filename=original_filename,
        stored_filename=stored_filename,
        algorithm_used=algorithm,
        user_id=current_user.id,
        encrypted_data=final_data
    )
    db.session.add(new_file_record)
    db.session.commit()

    session['last_metrics'] = metrics
    session['last_filename'] = stored_filename

    log_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'user_id': current_user.id,
        'username': current_user.username,
        'operation': metrics['operation'],
        'algorithm': metrics['algorithm'],
        'execution_time_s': metrics['time'],
        'output_size_bytes': metrics['size'],
        'original_filename': original_filename
    }
    # new thread for parralel
    threading.Thread(target=log_performance, args=(log_data,)).start()
    return redirect(url_for('results'))


@app.route('/decrypt/<int:file_id>', methods=['POST'])
@login_required
def decrypt(file_id):
    file_record = SecureFile.query.get_or_404(file_id)

    # --- UPDATED: CRITICAL Security Check ---
    # User must be the owner OR the file must be shared with them.
    is_owner = file_record.user_id == current_user.id
    is_shared = file_record in current_user.files_shared_with_me

    if not is_owner and not is_shared:
        abort(403)  # Forbidden

    # --- Decryption logic remains the same ---
    password = request.form.get('password')
    algorithm = file_record.algorithm_used

    if not password:
        flash('Password is required.', 'error')
        return redirect(url_for('dashboard'))

    #    try:
    #        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.stored_filename)
    #        with open(encrypted_file_path, 'rb') as f_in:
    #            encrypted_data_with_salt = f_in.read()
    #    except FileNotFoundError:
    #        flash('Error: File not found on server.', 'error')
    #        if is_owner: # Only owner can delete a broken record
    #            db.session.delete(file_record)
    #            db.session.commit()
    #        return redirect(url_for('dashboard'))

    encrypted_data_with_salt = file_record.encrypted_data
    start_time = time.perf_counter()
    try:
        salt = encrypted_data_with_salt[:SALT_SIZE]
        key = get_key_from_password(password, salt, algorithm)
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
        flash('Decryption failed. Please check your password.', 'error')
        return redirect(url_for('dashboard'))

    end_time = time.perf_counter()
    metrics = {
        'operation': 'Decryption',
        'algorithm': algorithm,
        'time': end_time - start_time,
        'size': len(decrypted_data)
    }

    output_filename = f"decrypted_{file_record.original_filename}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted_data)

    session['last_metrics'] = metrics
    session['last_filename'] = output_filename

    log_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'user_id': current_user.id,
        'username': current_user.username,
        'operation': metrics['operation'],
        'algorithm': metrics['algorithm'],
        'execution_time_s': metrics['time'],
        'output_size_bytes': metrics['size'],
        'original_filename': file_record.original_filename
    }
    # thread start
    threading.Thread(target=log_performance, args=(log_data,)).start()

    return redirect(url_for('results'))


@app.route('/results')
@login_required
def results():
    metrics = session.pop('last_metrics', None)
    filename = session.pop('last_filename', None)
    if not metrics or not filename:
        return redirect(url_for('dashboard'))
    return render_template('results.html', metrics=metrics, filename=filename)


@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    """
    Serves files from the UPLOAD_FOLDER.
    This route now handles both encrypted and decrypted files.
    """
    if filename.startswith('decrypted_'):
        # This is a temporary decrypted file. The user must have just
        # successfully decrypted it, so we'll allow the download.
        pass
    else:
        # --- UPDATED: CRITICAL Security Check ---
        # This is a raw .enc file. Check if user owns it or has share access.
        file_record = SecureFile.query.filter_by(stored_filename=filename).first()
        if not file_record:
            abort(404)

        is_owner = file_record.user_id == current_user.id
        is_shared = file_record in current_user.files_shared_with_me

        if not is_owner and not is_shared:
            abort(403)  # Forbidden

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# --- NEW: Share Management Routes ---

@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file_record = SecureFile.query.get_or_404(file_id)

    # Security: ONLY the owner can manage sharing
    if file_record.user_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        username_to_share = request.form.get('username')
        user_to_share = User.query.filter_by(username=username_to_share).first()

        if not user_to_share:
            flash(f'User "{username_to_share}" not found.', 'error')
        elif user_to_share.id == current_user.id:
            flash('You cannot share a file with yourself.', 'error')
        elif file_record in user_to_share.files_shared_with_me:
            flash(f'File already shared with {user_to_share.username}.', 'info')
        else:
            # Add the share relationship
            file_record.users_shared_with.append(user_to_share)
            db.session.commit()
            flash(f'File successfully shared with {user_to_share.username}.', 'success')

        return redirect(url_for('share_file', file_id=file_id))

    # GET request: Show the sharing page
    users_with_access = file_record.users_shared_with.all()
    return render_template('share.html', file=file_record, users_with_access=users_with_access)


@app.route('/unshare/<int:file_id>/<int:user_id>', methods=['POST'])
@login_required
def unshare_file(file_id, user_id):
    file_record = SecureFile.query.get_or_404(file_id)
    user_to_unshare = User.query.get_or_404(user_id)

    # Security: ONLY the owner can manage sharing
    if file_record.user_id != current_user.id:
        abort(403)

    # Remove the share relationship
    if user_to_unshare in file_record.users_shared_with:
        file_record.users_shared_with.remove(user_to_unshare)
        db.session.commit()
        flash(f'Access revoked for {user_to_unshare.username}.', 'success')
    else:
        flash(f'{user_to_unshare.username} did not have access.', 'info')

    return redirect(url_for('share_file', file_id=file_id))


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
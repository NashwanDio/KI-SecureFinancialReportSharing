import os
import time
import uuid
import csv
import threading
import datetime
from flask import (
    Flask, render_template, request, send_from_directory,
    url_for, redirect, flash, abort, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# (Crypto imports are unchanged)
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

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

# (Key derivation functions are unchanged)
SALT_SIZE = 16
KEY_SIZES = {'AES': 16, 'DES': 8, 'RC4': 16}
IV_SIZES = {'AES': 16, 'DES': 8}

def get_key_from_password(password, salt, algorithm):
    key_size = KEY_SIZES.get(algorithm)
    if not key_size:
        raise ValueError("Invalid algorithm specified for key derivation")
    return PBKDF2(password, salt, dkLen=key_size)

# (Performance logging is unchanged)
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

# --- Database Models ---

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)

    # --- === THE FIX IS HERE === ---
    # We added lazy='dynamic' to the backrefs. This makes 'sent_friend_requests'
    # and 'received_friend_requests' queryable, so .filter_by() will work.
    requester = db.relationship('User', foreign_keys=[requester_id], backref=db.backref('sent_friend_requests', lazy='dynamic'))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_friend_requests', lazy='dynamic'))
    # --- === END OF FIX === ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    files = db.relationship('SecureFile', backref='owner', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_friends(self):
        approved_sent = Friendship.query.filter_by(requester_id=self.id, status='approved').all()
        approved_received = Friendship.query.filter_by(receiver_id=self.id, status='approved').all()
        friends = []
        for req in approved_sent:
            friends.append(req.receiver)
        for req in approved_received:
            friends.append(req.requester)
        return friends
    
    def get_friend_ids(self):
        friend_ids = set()
        approved_sent = Friendship.query.filter_by(requester_id=self.id, status='approved').all()
        for req in approved_sent:
            friend_ids.add(req.receiver_id)
        approved_received = Friendship.query.filter_by(receiver_id=self.id, status='approved').all()
        for req in approved_received:
            friend_ids.add(req.requester_id)
        return list(friend_ids)

    def get_friend_status(self, other_user):
        request = Friendship.query.filter(
            or_(
                (Friendship.requester_id == self.id) & (Friendship.receiver_id == other_user.id),
                (Friendship.requester_id == other_user.id) & (Friendship.receiver_id == self.id)
            )
        ).first()
        
        if not request:
            return 'none'
        return request.status


class SecureFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    algorithm_used = db.Column(db.String(10), nullable=False)
    upload_timestamp = db.Column(db.DateTime, server_default=db.func.now())
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, default=True, nullable=False)

class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), default='pending', nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('secure_file.id'), nullable=False)
    
    requester = db.relationship('User', backref='requests_made', lazy='joined')
    file = db.relationship('SecureFile', backref='requests_received', lazy='joined')


@login_manager.user_loader
def load_user(user_id):
    # This includes the fix for the LegacyAPIWarning
    return db.session.get(User, int(user_id))

# --- Auth Routes (Unchanged) ---
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
    # 1. Get files you own
    owned_files = SecureFile.query.filter_by(user_id=current_user.id).order_by(SecureFile.upload_timestamp.desc()).all()
    
    # 2. Get files shared with you (approved requests)
    approved_requests = AccessRequest.query.filter_by(
        requester_id=current_user.id,
        status='approved'
    ).all()
    shared_files = [req.file for req in approved_requests if req.file] # Added check for req.file
    
    # 3. Get all public files from other users
    public_files = SecureFile.query.filter(
        SecureFile.is_public == True,
        SecureFile.user_id != current_user.id
    ).order_by(SecureFile.upload_timestamp.desc()).all()
    
    # 4. Get private files from friends
    friend_ids = current_user.get_friend_ids()
    friends_files = []
    if friend_ids: # Only query if the user has friends
        friends_files = SecureFile.query.filter(
            SecureFile.is_public == False,
            SecureFile.user_id.in_(friend_ids)
        ).order_by(SecureFile.upload_timestamp.desc()).all()

    # 5. Get a set of file IDs you have already requested (to change button state)
    your_requests = AccessRequest.query.filter_by(requester_id=current_user.id).all()
    # We create a dictionary of {file_id: status} for easy lookup in the template
    request_status_map = {req.file_id: req.status for req in your_requests}

    return render_template('dashboard.html',
                           owned_files=owned_files,
                           shared_files=shared_files,
                           public_files=public_files,
                           friends_files=friends_files,
                           request_status_map=request_status_map
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
    is_public = (visibility == 'public')

    if not all([file, password, algorithm, visibility]):
        flash('Missing file, password, algorithm, or visibility setting', 'error')
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

    metrics = { 'operation': 'Encryption', 'algorithm': algorithm, 'time': end_time - start_time, 'size': len(final_data) }
    original_filename = file.filename
    
    new_file_record = SecureFile(
        original_filename=original_filename,
        algorithm_used=algorithm,
        user_id=current_user.id,
        encrypted_data=final_data,
        is_public=is_public
    )
    db.session.add(new_file_record)
    db.session.commit()

    session['last_metrics'] = metrics
    session['last_filename'] = f"decrypted_{original_filename}"

    log_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'user_id': current_user.id, 'username': current_user.username,
        'operation': metrics['operation'], 'algorithm': metrics['algorithm'],
        'execution_time_s': metrics['time'], 'output_size_bytes': metrics['size'],
        'original_filename': original_filename
    }
    threading.Thread(target=log_performance, args=(log_data,)).start()
    return redirect(url_for('results'))


@app.route('/decrypt/<int:file_id>', methods=['POST'])
@login_required
def decrypt(file_id):
    file_record = SecureFile.query.get_or_404(file_id)
    is_owner = file_record.user_id == current_user.id
    is_approved = AccessRequest.query.filter_by(
        requester_id=current_user.id,
        file_id=file_record.id,
        status='approved'
    ).first() is not None

    if not is_owner and not is_approved:
        flash('You do not have permission to access this file.', 'error')
        return redirect(url_for('dashboard'))

    password = request.form.get('password')
    algorithm = file_record.algorithm_used
    if not password:
        flash('Password is required.', 'error')
        return redirect(url_for('dashboard'))

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

    metrics = { 'operation': 'Decryption', 'algorithm': algorithm, 'time': end_time - start_time, 'size': len(decrypted_data) }
    output_filename = f"decrypted_{file_record.original_filename}"
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted_data)

    session['last_metrics'] = metrics
    session['last_filename'] = output_filename

    log_data = {
        'timestamp': datetime.datetime.now().isoformat(),
        'user_id': current_user.id, 'username': current_user.username,
        'operation': metrics['operation'], 'algorithm': metrics['algorithm'],
        'execution_time_s': metrics['time'], 'output_size_bytes': metrics['size'],
        'original_filename': file_record.original_filename
    }
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
    if not filename.startswith('decrypted_'):
        flash("Invalid download link.", "error")
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# --- API Routes (Unchanged from Iteration 3) ---
@app.route('/api/friend_action/<int:user_id>', methods=['POST'])
@login_required
def friend_action(user_id):
    user_to_action = User.query.get_or_404(user_id)
    if user_to_action.id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot action yourself'}), 400
    action = request.json.get('action')
    existing_request = Friendship.query.filter(
        or_(
            (Friendship.requester_id == current_user.id) & (Friendship.receiver_id == user_to_action.id),
            (Friendship.requester_id == user_to_action.id) & (Friendship.receiver_id == current_user.id)
        )
    ).first()

    if action == 'request':
        if existing_request:
            return jsonify({'success': False, 'error': 'Request already pending or user is already a friend.'}), 400
        new_request = Friendship(requester_id=current_user.id, receiver_id=user_to_action.id, status='pending')
        db.session.add(new_request)
        db.session.commit()
        flash(f"Friend request sent to {user_to_action.username}.", "success")
        return jsonify({'success': True, 'new_status': 'pending'})

    if not existing_request:
        return jsonify({'success': False, 'error': 'No friendship record found.'}), 404

    if action == 'cancel':
        if existing_request.status == 'pending' and existing_request.requester_id == current_user.id:
            db.session.delete(existing_request)
            db.session.commit()
            flash("Friend request canceled.", "info")
            return jsonify({'success': True, 'new_status': 'none'})
        else:
            return jsonify({'success': False, 'error': 'Cannot cancel this request.'}), 403

    if action == 'remove':
        if existing_request.status == 'approved':
            db.session.delete(existing_request)
            db.session.commit()
            flash(f"Removed {user_to_action.username} from friends.", "success")
            return jsonify({'success': True, 'new_status': 'none'})
        else:
            return jsonify({'success': False, 'error': 'Cannot remove a non-friend.'}), 403
            
    return jsonify({'success': False, 'error': 'Invalid action.'}), 400

@app.route('/api/get_notifications')
@login_required
def api_get_notifications():
    notifications = []
    # 1. Get pending friend requests
    friend_requests = Friendship.query.filter_by(
        receiver_id=current_user.id,
        status='pending'
    ).all()
    for req in friend_requests:
        notifications.append({
            'id': req.id,
            'type': 'friend',
            'text': f"<strong>{req.requester.username}</strong> sent you a friend request."
        })
    
    # 2. Get pending file access requests (for files we OWN)
    file_requests = AccessRequest.query.join(SecureFile).filter(
        SecureFile.user_id == current_user.id,
        AccessRequest.status == 'pending'
    ).all()
    for req in file_requests:
        # Check if file or requester still exists
        if req.requester and req.file:
            notifications.append({
                'id': req.id,
                'type': 'file',
                'text': f"<strong>{req.requester.username}</strong> requested access to <strong>{req.file.original_filename}</strong>."
            })
    notifications.sort(key=lambda x: x['id'], reverse=True)
    return jsonify({
        'total_pending_count': len(notifications),
        'notifications': notifications
    })

@app.route('/api/respond_friend_request/<int:request_id>', methods=['POST'])
@login_required
def api_respond_friend(request_id):
    action = request.json.get('action')
    if action not in ['approve', 'deny']:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    friend_request = Friendship.query.get_or_404(request_id)
    if friend_request.receiver_id != current_user.id:
        return jsonify({'success': False, 'error': 'Not authorized'}), 403
    if action == 'approve':
        friend_request.status = 'approved'
        db.session.commit()
    else: # 'deny'
        db.session.delete(friend_request)
        db.session.commit()
    return jsonify({'success': True})

@app.route('/api/respond_file_request/<int:request_id>', methods=['POST'])
@login_required
def api_respond_file(request_id):
    action = request.json.get('action')
    if action not in ['approve', 'deny']:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    access_request = AccessRequest.query.get_or_404(request_id)
    if access_request.file.owner.id != current_user.id:
        return jsonify({'success': False, 'error': 'Not authorized'}), 403
    if action == 'approve':
        access_request.status = 'approved'
        db.session.commit()
    else: # 'deny'
        access_request.status = 'denied'
        db.session.commit()
    return jsonify({'success': True})


@app.route('/api/request_file_access/<int:file_id>', methods=['POST'])
@login_required
def api_request_file_access(file_id):
    file_to_request = SecureFile.query.get_or_404(file_id)
    
    # Check if user already owns it
    if file_to_request.user_id == current_user.id:
        return jsonify({'success': False, 'error': 'You own this file'}), 400
        
    # Check if a request already exists
    existing_request = AccessRequest.query.filter_by(
        requester_id=current_user.id,
        file_id=file_id
    ).first()
    
    if existing_request:
        return jsonify({'success': False, 'error': 'Request already sent', 'status': existing_request.status}), 400
        
    # Create new request
    new_request = AccessRequest(
        requester_id=current_user.id,
        file_id=file_id,
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit()
    
    return jsonify({'success': True, 'status': 'pending'})


# --- Main ---
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)


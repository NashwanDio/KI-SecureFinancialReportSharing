# KI-SecureFinancialReportSharing

Prerequisites :

```sudo apt update```

```sudo apt install python3 python3-pip python3-venv```

Installation :
```git clone https://github.com/NashwanDio/KI-SecureFinancialReportSharing.git```

```python3 -m venv venv```

```source venv/bin/activate```

```pip install -r requirements.txt```

Run the app :
```python3 app.py```

if this is the output then you're good

```* Serving Flask app 'app' ```

```* Running on http://127.0.0.1:5000```

```(Press CTRL+C to quit)```


---
## Background

Organisations frequently exchange confidential financial reports containing sensitive details such as budgets and project audits. Protecting these files from unauthorized access is critical. This web application allows secure upload, encrypted storage, sharing, and controlled retrieval of financial reports using symmetric encryption.

---

## Features

- User registration and login with hashed passwords
- Upload confidential files (Excel reports, profile images, company logo)
- Symmetric encryption (AES, DES, RC4 using non-ECB mode: CBC/CFB/OFB/CTR)
- Encrypted file storage on the server and database
- Share files with authorized registered users using database permissions
- Authenticated retrieval and decryption of shared files
- Performance comparison for encryption algorithms (time, size, etc.)

---

## Project Structure

```
├── app.py
├── templates/
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── share.html
│   ├── forgotpassword.html
│   └── results.html
├── static/
│   └── assets and things
└── README.md
```

---

## Usage Guidelines

### 1. Register a New User

- Go to the registration page.
- Fill in username, password, and (optionally) upload a profile image.
- Passwords are securely hashed before storing.

**Screenshot Placeholder:**  
_Insert screenshot of registration page here: ![Registration](screenshots/register.png)_

---

### 2. Login

- Go to login page, enter credentials.
- Successful logins redirect to dashboard.

**Screenshot Placeholder:**  
_Insert screenshot of login page here: ![Login](screenshots/login.png)_

---

### 3. Upload a Financial Report

- From dashboard, click "Upload File".
- Select an Excel file (using provided template).
- Choose encryption algorithm (AES, DES, RC4) and cipher mode (CBC/CFB/OFB/CTR).
- File is encrypted and stored on the server; report content is encrypted in the database.

**Screenshot Placeholder:**  
_Insert screenshot of file upload workflow here: ![Upload](screenshots/upload.png)_

---

### 4. Share a Report

- Click "Share" next to any uploaded file.
- Enter the recipient’s username to grant access.
- Shared users can view/decrypt the file once authenticated.

**Screenshot Placeholder:**  
_Insert screenshot of sharing mechanism here: ![Share](screenshots/share.png)_

---

### 5. Retrieve and Decrypt File

- Shared reports are listed on user’s dashboard.
- Authorized users can click "Download" or "Decrypt" to access the original file.

**Screenshot Placeholder:**  
_Insert screenshot of file retrieval/decryption here: ![Retrieve](screenshots/retrieve.png)_

---

## Performance Comparison

Encryption time, decryption time, and ciphertext size for AES, DES, and RC4 algorithms are recorded for all file types (Excel, images). Results are visualized below.

**Screenshot Placeholder:**  
_Insert screenshot of results table/chart here: ![Results](screenshots/results.png)_

---

Here’s how each **Security Notes** and **Troubleshooting** item in the README maps to code sections:

***

## Security Notes

- **Cryptographic keys are never hard-coded:**
  - Key derivation uses user-supplied passwords and random salts:
    ```python
    def get_key_from_password(password, salt, algorithm):
        # key size determined by algorithm, derived via PBKDF2
        return PBKDF2(password, salt, dkLen=keysize)
    ```
    Called in both encryption and decryption logic, e.g.:
    ```python
    salt = get_random_bytes(SALT_SIZE)
    key = get_key_from_password(password, salt, algorithm)
    ```

- **Access control is managed by database permissions:**
  - File sharing and access management:
    ```python
    fileshares = db.Table('fileshares', ...)
    # Sharing a file with another user
    filerecord.users_shared_with.append(usertoshare)
    # Checking access when downloading
    isowner = filerecord.userid == current_user.id
    isshared = filerecord in current_user.files_shared_with_me
    if not isowner and not isshared:
        abort(403)
    ```

- **All encryption/decryption operations are logged for analysis:**
  - Performance is logged with operation details:
    ```python
    def log_performance(log_data):
        # Appends to log file with threading lock
        ...
    threading.Thread(target=log_performance, args=(log_data,)).start()
    ```

***

## Troubleshooting

- **Double-check all environment variables and database settings:**
  - Database URI and app secrets are loaded/configured near the top:
    ```python
    app.config["SECRET_KEY"] = os.urandom(24)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
    ```

- **If uploads fail, ensure permissions on `static/uploads` are correct:**
  - Folder is created if missing (see `if __name__ == "__main__":`)
    ```python
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    ```
    If file writes fail, check filesystem permissions for this folder.



## Contributors

| Name                                 | NRP (SID)    |
|---------------------------------------|--------------|
| Nashwan Rasyid Muhammad               | 5025221004   |
| Mohammad Hanif Furqan Aufa Putra      | 5025221161   |
| Ariq Javier Ramadhani Rahim           | 5025221267   |
| Adelia Putri Kamaski                  | 5025221320   |

---

## License

This project is for academic/educational purposes.

---

## Acknowledgments

- Cryptography libraries used: PyCryptoDome, cryptography
- Assignment template provided by the course instructor



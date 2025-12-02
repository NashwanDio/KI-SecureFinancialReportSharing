from tinydb import TinyDB, Query
import os

# Initialize the NoSQL database
# This will create a file named 'keystore.json' in your project folder
db = TinyDB('keystore.json')
UserKey = Query()

def store_private_key(user_id, encrypted_private_key_pem):
    """
    Stores the Encrypted Private Key for a specific user.
    If the user already has a key, it updates it.
    """
    # 1. Convert byte data to string if it isn't already (JSON can't store bytes directly)
    if isinstance(encrypted_private_key_pem, bytes):
        encrypted_private_key_pem = encrypted_private_key_pem.decode('utf-8')

    # 2. Check if this user already has a key entry
    existing_user = db.search(UserKey.user_id == user_id)

    if existing_user:
        # Update existing record
        db.update({'private_key': encrypted_private_key_pem}, UserKey.user_id == user_id)
    else:
        # Insert new record
        db.insert({'user_id': user_id, 'private_key': encrypted_private_key_pem})

def get_private_key(user_id):
    """
    Retrieves the Encrypted Private Key for a specific user.
    Returns None if user has no keys.
    """
    result = db.search(UserKey.user_id == user_id)
    
    if result:
        # Return the key (result is a list, we take the first match)
        return result[0]['private_key']
    return None

def delete_user_key(user_id):
    """
    Removes a user's keys from the keystore (used when deleting a user).
    """
    db.remove(UserKey.user_id == user_id)
import hashlib, os, jwt
import jwt
import datetime
import base64

def hash_pass( password ):
    salt = hashlib.sha256(os.urandom(True)).digest()
    return hash_n_salt(password, salt)

def hash_n_salt(plaintext, salt) -> bytes:
    assert(type(plaintext) == str)
    assert(type(salt) == bytes)
    assert(len(salt) == 32)
    pwdhash = hashlib.pbkdf2_hmac('sha256', plaintext.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt + pwdhash)

def verify_pass(provided_password, stored_password) -> bool:
    assert(type(provided_password) == str)
    assert(type(stored_password) == bytes)

    stored_password_decoded = base64.b64decode(stored_password)
    assert(len(stored_password_decoded) == 32 + 32)
    salt = stored_password_decoded[:32]
    pwdhash = hash_n_salt(provided_password, salt)

    print(provided_password)
    print(pwdhash)
    print(stored_password)

    return pwdhash == stored_password

def password_reset_jwt(key, username):
    from decouple import config
    key = hash_n_salt(config('SECRET_KEY'), 'jwt_key'.encode('utf-8'))
    payload = {
        'sub': username,
        'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)
    }
    encoded = jwt.encode(payload, key, algorithm="HS256")
    return encoded.decode('utf-8')
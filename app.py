# pylint: disable=E0401 C0301 C0116
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# In-memory storage for simplicity (not suitable for production)
users = {}

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data_symmetric(key, data):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    return iv, cipher_text, tag

def decrypt_data_symmetric(key, data, tag, iv):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize_with_tag(tag)

def encrypt_data_asymmetric(public_key, data):
    cipher_text = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

def decrypt_data_asymmetric(private_key, cipher_text):
    plaintext = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    master_password = request.form['master_password']

    private_key, public_key = generate_key_pair()
    master_key_salt = os.urandom(16)
    master_key = derive_key_from_password(master_password, master_key_salt)

    users[username] = {
        'private_key': private_key,
        'public_key': public_key,
        'master_key': master_key,
        'master_key_salt': master_key_salt,
        'passwords': {}
    }

    return redirect(url_for('dashboard', username=username))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    master_password = request.form['master_password']

    if username in users:
        user = users[username]
        master_key = derive_key_from_password(master_password, user['master_key_salt'])

        # Check if master password is correct
        if master_key == user['master_key']:
            return redirect(url_for('dashboard', username=username))

    return redirect(url_for('index'))

@app.route('/dashboard/<username>')
def dashboard(username):
    user = users.get(username)
    if user:
        return render_template('dashboard.html', username=username, passwords=user['passwords'])
    else:
        return redirect(url_for('index'))

@app.route('/add_password', methods=['POST'])
def add_password():
    username = request.form['username']
    website = request.form['website']
    password = request.form['password']

    user = users.get(username)
    if user:
        symmetric_key = os.urandom(32)
        iv, encrypted_password, tag = encrypt_data_symmetric(symmetric_key, password.encode())
        encrypted_symmetric_key = encrypt_data_asymmetric(user['public_key'], symmetric_key)

        user['passwords'][website] = {
            'iv': iv,
            'encrypted_password': encrypted_password,
            'tag': tag,
            'encrypted_symmetric_key': encrypted_symmetric_key
        }

    return redirect(url_for('dashboard', username=username))

@app.route('/get_password/<username>/<website>')
def get_password(username, website):
    user = users.get(username)
    if user and website in user['passwords']:
        password_entry = user['passwords'][website]
        decrypted_symmetric_key = decrypt_data_asymmetric(user['private_key'], password_entry['encrypted_symmetric_key'])
        decrypted_password = decrypt_data_symmetric(decrypted_symmetric_key, password_entry['encrypted_password'], password_entry['tag'], password_entry['iv'])
        return jsonify({
            'website': website,
            'username': username,
            'password': decrypted_password.decode()
        })

    return jsonify({'error': 'Password not found'})

if __name__ == "__main__":
    app.run(debug=True, port=8080)

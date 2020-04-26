import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256

from flask import Flask, request
import requests
import json

BLOCK_SIZE = 16

SECRET_KEY = 'stackoverflow.com'


def unpad(s): return s[:-ord(s[len(s) - 1:])]


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


app = Flask(__name__)


def pad(s): return s + (BLOCK_SIZE - len(s) %
                        BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


@app.route('/app', methods=['POST'])
def check_credentials():
    # Build our shared app server key from SHA256 hash of stackoverflow.com
    app_server_hash_object = SHA256.new(data=SECRET_KEY.encode())
    app_server_key = str(app_server_hash_object.hexdigest())

    encrypted_data = request.json
    print('app server: data received {}'.format(encrypted_data))
    encrypted_str = encrypted_data['cyphertext']
    print(encrypted_str)
    print(encrypted_str.encode('utf-8'))
    decrypted = decrypt(encrypted_str.encode('utf-8'), app_server_key)
    return decrypted


@app.teardown_request
def show_teardown(exception):
    print('after with block')


with app.test_request_context():
    print('during with block')

# teardown functions are called after the context with block exits

with app.test_client() as client:
    client.get('/')
    # the contexts are not popped even though the request ended
    print(request.path)

# the contexts are popped and teardown functions are called after
# the client with block exits

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256

from flask import Flask, request
import requests
import json

OAUTH_SERVER = 'http://127.0.0.1:5000/oauth_dummy_test'

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


def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw).encode("utf-8")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


@app.route('/auth', methods=['POST'])
def send_credentials():
    user_data = request.json
    print('auth server: data received {}'.format(user_data))
    password = user_data['password']

    print('auth server: sending credentials to oauth server')
    oauth_resp = requests.post(OAUTH_SERVER, json=user_data)

    print('auth server: received response from oauth server {}'
          .format(oauth_resp))
    oauth_data = oauth_resp.json()
    auth = oauth_data['auth']
    token = oauth_data['token']

    if auth == 'success':
        print('auth server: token received {}'.format(token))

        auth_resp = {'auth': 'success', 'token': token}
        auth_str = str(json.dumps(auth_resp))

        # Build our shared app server key from SHA256 hash of stackoverflow.com
        app_server_hash_object = SHA256.new(data=SECRET_KEY.encode())
        app_server_key = str(app_server_hash_object.hexdigest())

        # encrypt our stringified json using the app server key
        encrypted_auth_str = encrypt(auth_str, app_server_key)
        print('auth server: encrypted with shared app server key as ciphertext {}'
              .format(encrypted_auth_str))

        # Build our shared client key using the a SHA256 hash of the user's password
        client_hash_object = SHA256.new(data=password.encode())
        client_key = str(client_hash_object.hexdigest())

        # encrypt again the stringified json using the client key
        encrypted_client_str = encrypt(
            encrypted_auth_str.decode('utf-8'), client_key)
        print('auth server: encrypted with client key as ciphertext {}'
              .format(encrypted_client_str))

        return encrypted_client_str


@app.route('/oauth_dummy_test', methods=['POST'])
def dummy_server():
    data = request.json
    print('dummy oauth server: data received {}'.format(data))
    if 'user' in request.json and 'password' in request.json:
        print('dummy oauth server: sending credentials to auth server')
        return '{"auth":"success", "token":"dummy_token"}'
    else:
        print('dummy oauth server: no credentials found, sending failure')
        return '{"auth":"fail", "token":""}'


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

import base64
import hashlib
import requests
import json
from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256

client = Flask(__name__)
client.config["DEBUG"] = True

AUTH_IP = "127.0.0.1:5000/auth" # Will add IP once servers are set up
APP_IP = "127.0.0.1:5000/app" # Will add IP once servers are set up

def unpad(s): return s[:-ord(s[len(s) - 1:])]


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


@client.route('/', methods=['GET'])
def login():
    return render_template('login.html')

@client.route('/', methods=['POST'])
def login_attempt():

    # Takes the username and password entered in login.html
    username = request.form['username']
    password = request.form['password']

    # Creates a json token to send to the authentication server
    user_data = {"username": username, "password": password}
    user_data = json.dumps(user_data)
    auth_response = requests.post(AUTH_IP, json=user_data)

    # Creates a SHA256 hash of the password and uses that as the key to 
    # decrypt the token form the authentication server
    client_hash_object = SHA256.new(data=password.encode())
    client_key = str(client_hash_object.hexdigest())
    decrypted_response = decrypt(auth_response, client_key)

    # Gets the application token from the decrypted authentication token and sends it
    # to the application
    auth_data = decrypted_response.json()
    app_token = auth_data['token']
    app_response = requests.post(APP_IP, json=app_token)
    return app_response

client.run()

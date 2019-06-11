from uuid import uuid4
import urllib
import base64
import json

from nacl.public import Box
import nacl.encoding
import nacl.signing
import requests

from flask import Flask, session, redirect, url_for, request, abort

app = Flask(__name__)
app.secret_key = "super secret key for sessions"

app.config['private_key'] = nacl.signing.SigningKey.generate().encode(nacl.encoding.Base64Encoder)

@app.route('/')
def login():
    private_key = nacl.signing.SigningKey(app.config['private_key'], encoder=nacl.encoding.Base64Encoder)
    public_key = private_key.verify_key
    redirect_url = 'https://login.threefold.me'
    state = str(uuid4())
    session['state'] = state
    params = {
        'state' : state,
        'appid' : 'python_app',
        'scope' : 'user:email',
        'redirecturl' : 'http://127.0.0.1:5000/callback',
        'publickey' : public_key.to_curve25519_public_key().encode(encoder=nacl.encoding.Base64Encoder)
    }


    return redirect("{0}?{1}".format(redirect_url, urllib.parse.urlencode(params)), code=302)

@app.route('/callback')
def callback():
    signedhash = request.args.get('signedhash')
    username = request.args.get('username')
    data = request.args.get('data')

    if signedhash is None or username is None or data is None:
        return abort(400)
    data = json.loads(data)

    res = requests.get('https://login.threefold.me/api/users/{0}'.format(username), {'Content-Type':'application/json'})
    if res.status_code != 200:
        return abort(400, {'message': 'Error getting user pub key'})

    user_pub_key = nacl.signing.VerifyKey(res.json()['publicKey'], encoder=nacl.encoding.Base64Encoder)
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    private_key = nacl.signing.SigningKey(app.config['private_key'], encoder=nacl.encoding.Base64Encoder)

    state = user_pub_key.verify(base64.b64decode(signedhash)).decode()

    if state != session['state']:
        return abort(400, {'message': 'Invalid state. not matching one in user session'})
    import ipdb; ipdb.set_trace()
    box = Box(
        private_key.to_curve25519_private_key(),
        user_pub_key.to_curve25519_public_key()
    )

    try:
        decrypted = box.decrypt(ciphertext, nonce)
        result = json.loads(decrypted)
        email = result['email']['email']
        emailVerified = result['email']['verified']
        if not emailVerified:
            return abort(400, {'message': 'Email not verified'})
        return email
    except:
        return abort(400, {'message': 'Error decrypting'})


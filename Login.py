# -*- coding: utf-8 -*-

import base64
from functools import wraps
import hashlib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from flask import Flask, session, jsonify, request, escape
import redis

redis_connections = redis.Redis()
app = Flask(__name__)

app.config['SECRET_KEY'] = 'mapia'


@app.route('/')
def index():
    return 'Safety Login'

ID = []
PASSWORD = []

@app.route('/api/user/signup', methods=['POST'])
def signup():
    print request.json
    # id = request.form['id']
    # password = request.form['password']
    # ID.append(id)
    # PASSWORD.append(password)

    return jsonify({ 'message': u'회원가입되었습니다.' }), 200

@app.route('/api/user/login', methods=['PUT', 'GET'])
def login():
    if request.method == 'PUT':
        encrypted_id = base64.b64decode(request.form['id'])
        encrypted_password = base64.b64decode(request.form['password'])

        session_key = base64.b64decode(escape(session['private_key']))
        private_key = PKCS1_OAEP.new(RSA.importKey(session_key))

        decrypted_id = private_key.decrypt(encrypted_id)
        decrypted_password = private_key.decrypt(encrypted_password)

        # decrypted_phone과 decrypted_password를 이미 DB에 저장된 값과 비교하여 확인한다.
        # 사용자 정보로부터 사용자 구분지을 수 있는 hash 값을 생성한다.
        # hash 값을 key로 하여 Redis에 사용자 정보를 저장한다.

        uid = None
        try:
            uid = ID.index(decrypted_id)
            if PASSWORD[uid] != decrypted_password:
                raise ValueError('Could not find correct user!')
        except:
            return jsonify({ 'message': u'아이디 또는 비밀번호가 틀렸습니다.' }), 401

        user_hash = hashlib.sha1(str(uid)).hexdigest()
        user_info = { 'id': ID[uid]}

        redis_connections.set(user_hash, user_info)
        session['token'] = user_hash

        return jsonify({ 'message': u'로그인되었습니다.' }), 200

    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    session['private_key'] = base64.b64encode(private_key.exportKey('DER'))
    return jsonify({ 'public_key': base64.b64encode(public_key.exportKey('DER')) }), 200

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = session.get('token')
        if session_token is None:
            return jsonify({ 'message': u'로그인해주세요.' }), 401

        session_token = escape(session_token)
        if redis_connections.get(session_token) is None:
            return jsonify({ 'message': u'로그인해주세요.' }), 401

        return f(*args, **kwargs)
    return decorated_function



@app.route('/api/user/profile', methods=['GET'])
@login_required
def profile():
    session_token = escape(session.get('token'))
    user_info = redis_connections.get(session_token)
    return jsonify(user_info), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8081,debug=True)



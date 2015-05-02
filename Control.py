# -*- coding: utf-8 -*-

import os
from flask import Flask, abort, request, jsonify, g, url_for, session, escape
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
import redis
import json
import base64
from functools import wraps
import hashlib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from werkzeug import secure_filename
import Model

UPLOAD_FOLDER = './img/'
ALLOWED_EXTENSIONS = set(['jpg','png'])

# initialization

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mapia'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
 	
# extensions
auth = HTTPBasicAuth()


redis_connections = redis.Redis()
db = SQLAlchemy(app)

redis_username = []
redis_password = []

#temp decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print request.headers
        session_token = session.get('token')
        if session_token is None:
            return jsonify({ 'message': u'로그인해주세요.' }), 401

        session_token = escape(session_token)
        if redis_connections.get(session_token) is None:
            return jsonify({ 'message': u'로그인해주세요.' }), 401

        return f(*args, **kwargs)
    return decorated_function




@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = Model.User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with userd/password
        user = Model.User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

#file upload
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route("/users/self/profile_pic", methods=['GET','POST'])
@auth.login_required
def post_profile_pic():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = g.user.username + secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({'code':'200'})
        return jsonify({'code':'404'})
    else:
        return jsonify({'profile_pic':'image return'})




@app.route('/test',methods=['GET','POST'])
def hello():
    print request.headers
    print request.authorization
    return 'hi'

@app.route('/users/<int:id>')
def get_user(id):
    user = Model.User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/auth/login',methods=['POST','GET'])
def login():
    if request.method == 'POST':
        encrypted_id = base64.b64decode(request.json['username'])
        encrypted_password = base64.b64decode(request.json['password'])

        session_key = base64.b64decode(escape(session['private_key']))
        private_key = PKCS1_OAEP.new(RSA.importKey(session_key))

        decrypted_id = private_key.decrypt(encrypted_id)
        decrypted_password = private_key.decrypt(encrypted_password)

        # decrypted_phone과 decrypted_password를 이미 DB에 저장된 값과 비교하여 확인한다.
        # 사용자 정보로부터 사용자 구분지을 수 있는 hash 값을 생성한다.
        # hash 값을 key로 하여 Redis에 사용자 정보를 저장한다.

        uid = None
        try:
            uid = redis_username.index(decrypted_id)
            if redis_password[uid] != decrypted_password:
                raise ValueError('Could not find correct user!')
        except:
            print 'ID 또는 PW 불일치'
            return jsonify({ 'message': u'아이디 또는 비밀번호가 틀렸습니다.' }), 401

        user_hash = hashlib.sha1(str(uid)).hexdigest()
        user_info = redis_username[uid]

        redis_connections.set(user_hash, user_info)
        session['token'] = user_hash

        return jsonify({ 'message': u'로그인되었습니다.' }), 200

    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    session['private_key'] = base64.b64encode(private_key.exportKey('DER'))
    return jsonify({ 'public_key': base64.b64encode(public_key.exportKey('DER')) }), 200




@app.route('/auth/signup/<username>')
def check_duplicate_username(username):
	if Model.User.query.filter_by(username=username).first() is not None:
		return jsonify({'exist':'true'})
	else:
		return jsonify({'exist':'false'})


@app.route('/auth/signup', methods=['POST'])
def sign_up():
    username = request.json['username']
    password = request.json['password']
    print username, password
    if username is None or password is None:
        return jsonify({'message':'missing arguments'}), 400
    if Model.User.query.filter_by(username=username).first() is not None:
        return jsonify({'message':'existing user'}), 400

    user = Model.User(username=username)
    user.hash_password(password)

    #Redis에 저장
    redis_username.append(username)
    redis_password.append(password)

    db.session.add(user)
    db.session.commit()
    g.user = user
    return jsonify({ 'message': u'회원가입되었습니다.'}), 200
            # {'Location': url_for('get_user', id=user.username, _external=True)})


#로그인 여부 확인
@app.route('/auth/profile', methods=['GET'])
@login_required
def profile():
    session_token = escape(session.get('token'))
    user_info = redis_connections.get(session_token)
    print user_info

    return jsonify({'message': u'welcome '+user_info}), 200



@app.route('/post', methods=['POST','GET'])
@auth.login_required
def post():
    if request.method == 'POST':
        posts = request.json.get('posts')
        for each_post in posts:
            content = each_post['content']
            lat = each_post['lat']
            lng = each_post['lng']
            # tags = each_post['tags']
            # to = each_post['to']

            user = Model.User.query.filter_by(username=g.user.username).first() 
            db.session.add(user)
            facebook_post = Model.Post(user=user,content=content, lat=lat, lng=lng)
            db.session.add(facebook_post)

        db.session.commit()
        db.session.flush()
        return (jsonify({'code':'201','desciption':'success'}))
    else:
        posts = Model.Post.query.filter_by(username=g.user.username).all()
        post_list = []
        for each_post in posts:
            post_list.append({'id':each_post.id,'username':each_post.username,'content':each_post.content,'lat':each_post.lat,'lng':each_post.lng})
        print post_list
        return jsonify({'posts': post_list})

@app.route('/comments/<int:postid>', methods=['GET','POST'])
@auth.login_required
def comment(postid):
    if request.method == 'POST':
        comments = request.json.get('comments')
        for each_comment in comments:
            content = each_comment['content']
            user = Model.User.query.filter_by(username=g.user.username).first() 
            db.session.add(user)

            post = Model.Post.query.filter_by(id=postid).first()
            db.session.add(post)

            comment = Model.Comment(user=user,content=content, post=post)
            db.session.add(comment)
        db.session.commit()
        db.session.flush()
        return (jsonify({'code':'201','desciption':'success'}))
    else:
        comments = Model.Comment.query.filter_by(postid=postid).all()
        comment_list = []
        for each_comment in comments:
            comment_list.append({'id':each_comment.id,'username':each_comment.username,'content':each_comment.content,'postid':each_comment.postid})
        print comment_list
        return jsonify({'comments': comment_list})


@app.route('/follows/<username>', methods=['GET','POST'])
@auth.login_required
def follow(username):
    if request.method == 'POST':
        follows = request.json.get('follows')
        for each_follow in follows:
            follow_to = each_follow['follow_to']
            follow_from_user = Model.User.query.filter_by(username=g.user.username).first() 
            db.session.add(follow_from_user)

            follow_to_user = Model.User.query.filter_by(username=follow_to).first() 
            db.session.add(follow_to_user)

            follow = Model.Follow(follow_from_user=follow_from_user, follow_to_user=follow_to_user)
            db.session.add(follow)

        db.session.commit()
        db.session.flush()

        return (jsonify({'code':'201','desciption':'success'}))
    else:
        follows = Model.Follow.query.filter_by(follow_from=username).all()
        follow_list = []
        for each_follow in follows:
            follow_list.append({'follow_to':each_follow.follow_to})
        print follow_list
        return jsonify({'follows': follow_list})





@app.route('/sns/facebook/post',methods=['POST','GET'])
@auth.login_required
def facebook_post():
    if request.method == 'POST':
        posts = request.json.get('posts')
        for each_post in posts:
            content = each_post['content']
            fb_id = each_post['fb_id']  
            # permanent_id = each_post['permanet_id']
            # display_url = each_post['display_url']
            # picture = each_post['picture']
            # video_url = each_post['videio_url']
            # attachment_urls = each_post['attachment_urls']
            # place = each_post['place']

            user = Model.User.query.filter_by(username=g.user.username).first() 

            db.session.add(user)

            facebook_post = Model.FacebookPost(content=content, fbid=fb_id, user=user)
            
            db.session.add(facebook_post)

        db.session.commit()
        db.session.flush()
        return (jsonify({'code':'201','desciption':'success'}))
    else:
        facebook_post = Model.FacebookPost.query.filter_by(username=g.user.username).all()
        post_list = []
        for each_post in facebook_post:
            print {'content':each_post.content,'fbid':each_post.fbid}
            post_list.append({'content':each_post.content,'fbid':each_post.fbid})
        print post_list
        return jsonify({'posts': post_list})





if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080,debug=True)





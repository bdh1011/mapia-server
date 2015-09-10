# -*- coding: utf-8 -*-

import os
from flask import render_template,  Flask, abort, request, jsonify, g, url_for, session, escape, send_from_directory
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
import redis
import json
import base64
from functools import wraps
import hashlib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from passlib.apps import custom_app_context as pwd_context

from werkzeug import secure_filename
from app import auth
from app import db
from app import app
from models import User, FacebookProfile, FacebookPost, Follow, Post, Photo #, Group, GroupMember, GroupType, Post, Photo, 
redis_username = []
redis_password = []

redis_connections = redis.Redis()

# user = User(username="admingadsdasdffasdf")
# user.hash_password("admin")
# try:
#     db.session.add(user)
#     db.session.commit()
# except:
    # pass

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.route("/sns/facebook/login", methods=['GET'])
def facebook_login():
	return render_template('facebook_login.html')


@app.route("/post/image", methods= ['POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            paths = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print paths
            file.save(paths)

            return jsonify({'message':u'Successfully Upload'})
    return jsonify({'message':u'Fail'})  


@app.route("/post/image/<filename>")
def get_file():
    return send_from_directory(app.confg['UPLOAD_FOLDER'], filename)



@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with userd/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

#file upload
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


@app.route("/users/self/profile_pic", methods=['GET','POST'])
@auth.login_required
def post_profile_pic():
    if request.method == 'POST':
        file = request.files['profile_pic']
        session_token = escape(session.get('token'))
        username = redis_connections.get(session_token)
        user = User.query.filter_by(username=username).first()

        if file and allowed_file(file.filename):
            filename = g.user.username + secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.profile_pic_filename = filename
            db.session.commit()

            return jsonify({'code':'200'})
        return jsonify({'code':'404'})
    else:
        session_token = escape(session.get('token'))
        username = redis_connections.get(session_token)
        user = User.query.filter_by(username=username).first()
        path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic_filename)
        return app.send_static_file(path)




@app.route('/test',methods=['GET','POST'])
def hello():
    print request.headers
    print request.authorization
    return 'hi'

@app.route('/users/<username>')
def get_user(id):
    user = User.query.get(username)
    if not user:
        abort(400)
    return jsonify({'username': user.username,
        'profile_pic_filename': user.profile_pic_filename})


@app.route('/auth/login',methods=['POST','GET'])
def login():
    if request.method == 'POST':
        encrypted_id = base64.b64decode(request.json['username'])
        encrypted_password = base64.b64decode(request.json['password'])

        session_key = base64.b64decode(escape(session['private_key']))
        private_key = PKCS1_OAEP.new(RSA.importKey(session_key))

        decrypted_id = private_key.decrypt(encrypted_id)
        decrypted_password = private_key.decrypt(encrypted_password)

        print "id : "+str(decrypted_id)
        print "pw : "+str(decrypted_password)
        # decrypted_phone과 decrypted_password를 이미 DB에 저장된 값과 비교하여 확인한다.
        # 사용자 정보로부터 사용자 구분지을 수 있는 hash 값을 생성한다.
        # hash 값을 key로 하여 Redis에 사용자 정보를 저장한다.

        user = User.query.filter_by(username=decrypted_id).first() 
        uid = None
        try:
            uid = redis_username.index(decrypted_id)
            if not user.verify_password(decrypted_password):
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
	if User.query.filter_by(username=username).first() is not None:
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
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'message':'existing user'}), 400

    user = User(username=username)
    user.hash_password(password)

    #Redis에 저장
    redis_username.append(username)
    redis_password.append(user.password_hash)
    print user.password_hash

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

@app.route('/auth/logout', methods=['GET'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': u'log out'}), 200


@app.route('/post', methods=['POST','GET'])
@login_required
def post():
    if request.method == 'POST':
        print request.json
        
        # session_token = escape(session.get('token'))
        # username = redis_connections.get(session_token)
        username="admin"
        maptype = request.json['maptype']
        content = request.json['postContent']
        latlng = request.json['postLatLng']
        print latlng
        user = User.query.filter_by(username=username).first() 
        # db.session.add(user)

        # print session_token, username, content, lat, lng
        if maptype == 'group':
            groupname = request.json['group']
            group = Group.query.filter_by(name=groupname).first() 
            post = Post(user=user,content=content, lat=lat, lng=lng, group=group, to=maptype)
            db.session.add(post)
            db.session.commit()
            db.session.flush()
        else:    
            post = Post(user=user,content=content, lat=lat, lng=lng, to=maptype)
            db.session.add(post)
            db.session.commit()
            db.session.flush()


        if 'filelist' in request.json:
            filelist = request.json['filelist']
            db.session.add(post)
            for each_file in filelist:
                photo = Photo(postid=post.id, filename=each_file)
                db.session.add(photo)
                print photo
                #should photo deep copied?
            db.session.commit()
            db.session.flush()
           

        return jsonify({'message':u'upload posting Successfully!'}),200
    else:

        map_type = request.args['map-type']
        center_latitude = request.args['center-latitude']
        center_longitude = request.args['center-longitude']
        map_level = request.args['map-level']

        session_token = escape(session.get('token'))
        username = redis_connections.get(session_token)
        posts = []

        print 'map_type : ',map_type

        if map_type == 'private':
            posts = Post.query.filter_by(username=username).all()

        #follow 하는 사람들이 올린 게시글
        elif map_type == 'follow':
            follow_list = Follow.query.filter_by(follow_from=username).all()
            for each_user in follow_list:
                posts.append(Post.query.filter_by(username=each_user.follow_to))

        #특정 Group에 올라온 게시글
        elif map_type == 'group':
            group = Group.query.filter_by(name=request.args['group'])
            posts = Post.query.filter_by(group=group)

        #Public 타입의 게시글
        elif map_type == 'public':
            posts = Post.query.filter_by(to='public')

        post_list = []
        for each in Photo.query.all():
            print each.id
            print each.postid
            print each.filename
        for each_post in posts:
            print 'post id : '+str(each_post.id)
            photo_list = Photo.query.filter_by(postid=each_post.id).all()
            print photo_list
            photo_name_list = []
            for each_photo_name in photo_list:
                photo_name_list.append(each_photo_name.filename)
            post_list.append({'id':each_post.id,'username':each_post.username,'content':each_post.content,'lat':each_post.lat,'lng':each_post.lng,'timestamp':each_post.timestamp,'photo_list':photo_name_list})
        print post_list
        return jsonify({'posts': post_list})

@app.route('/comments/<int:postid>', methods=['GET','POST'])
@auth.login_required
def comment(postid):
    if request.method == 'POST':
        comments = request.json.get('comments')
        for each_comment in comments:
            content = each_comment['content']
            user = User.query.filter_by(username=g.user.username).first() 
            db.session.add(user)

            post = Post.query.filter_by(id=postid).first()
            db.session.add(post)

            comment = Comment(user=user,content=content, post=post)
            db.session.add(comment)
        db.session.commit()
        db.session.flush()
        return (jsonify({'code':'201','desciption':'success'}))
    else:
        comments = Comment.query.filter_by(postid=postid).all()
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
            follow_from_user = User.query.filter_by(username=g.user.username).first() 
            db.session.add(follow_from_user)

            follow_to_user = User.query.filter_by(username=follow_to).first() 
            db.session.add(follow_to_user)

            follow = Follow(follow_from_user=follow_from_user, follow_to_user=follow_to_user)
            db.session.add(follow)

        db.session.commit()
        db.session.flush()

        return (jsonify({'code':'201','desciption':'success'}))
    else:
        follows = Follow.query.filter_by(follow_from=username).all()
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

            user = User.query.filter_by(username=g.user.username).first() 

            db.session.add(user)

            facebook_post = FacebookPost(content=content, fbid=fb_id, user=user)
            
            db.session.add(facebook_post)

        db.session.commit()
        db.session.flush()
        return (jsonify({'code':'201','desciption':'success'}))
    else:
        facebook_post = FacebookPost.query.filter_by(username=g.user.username).all()
        post_list = []
        for each_post in facebook_post:
            print {'content':each_post.content,'fbid':each_post.fbid}
            post_list.append({'content':each_post.content,'fbid':each_post.fbid})
        print post_list
        return jsonify({'posts': post_list})










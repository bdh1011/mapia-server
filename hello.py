import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth

from werkzeug import secure_filename
import Model

UPLOAD_FOLDER = './img/'
ALLOWED_EXTENSIONS = set(['jpg','png'])

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
 	
# extensions
auth = HTTPBasicAuth()

db = SQLAlchemy(app)

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

@app.route('/auth/login')
@auth.login_required #change username to username
def get_auth_token():
    print request.json
    token = g.user.generate_auth_token(360000)
    return jsonify({'token': token.decode('ascii'), 'duration':360000})


@app.route('/auth/signup/<username>')
def check_duplicate_username(username):
	if User.query.filter_by(username=username).first() is not None:
		return jsonify({'exist':'true'})
	else:
		return jsonify({'exist':'false'})


@app.route('/auth/signup', methods=['POST'])
def sign_up():
    username = request.json.get('username')
    password = request.json.get('password')
    print username, password
    if username is None or password is None:
        return (jsonify({'code':'400','description':'missing arguments'}))
    if Model.User.query.filter_by(username=username).first() is not None:
        return (jsonify({'code':'400','description':'existing user'}))
    user = Model.User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    g.user = user
    token = g.user.generate_auth_token(360000)
    return (jsonify({'code':'201','token':token }), 201)
            # {'Location': url_for('get_user', id=user.username, _external=True)})

@app.route('/users/self')
@auth.login_required
def get_user_self():
	return jsonify({'username':g.user.username})


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



@app.route('/users/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})






if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080,debug=True)





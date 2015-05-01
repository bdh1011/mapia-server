# -*- coding: utf-8 -*-

from flask.ext.sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context

from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from Control import db, app
import json, os





class Json(db.TypeDecorator):
    impl = db.String
    def process_bind_param(self, value, dialect):
        return json.dumps(value)
 
    def process_result_value(self, value, dialect):
        return json.loads(value)

class Location(db.TypeDecorator):
    impl = db.String
    lat = db.Integer
    lng = db.Integer



class User(db.Model):
    __tablename__ = 'user'
    username = db.Column(db.String(64), primary_key=True)
    password_hash = db.Column(db.String(64))
    profile_pic_filename = db.Column(db.String(64))
    register_timestamp = db.Column(db.DateTime, default=db.func.now())
    update_timestamp = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())



    facebook_token = db.Column(db.String(64))
    instagram_token = db.Column(db.String(64))
    twitter_token = db.Column(db.String(64))
    foursquare_token = db.Column(db.String(64))
    google_token = db.Column(db.String(64))

    facebook_post = db.relationship('FacebookPost', backref='user',
                                lazy='dynamic')

    post = db.relationship('Post', backref='user',
                                lazy='dynamic')

    comment = db.relationship('Comment', backref='user',
                                lazy='dynamic')

    follow_to = db.relationship('Follow', backref='follow_to_user',
                                lazy='dynamic',foreign_keys = 'Follow.follow_to')

    follow_from = db.relationship('Follow', backref='follow_from_user',
                                lazy='dynamic',foreign_keys = 'Follow.follow_from')

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=360000):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'username': self.username})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


class FacebookProfile(db.Model):
    __tablename__ = 'sns'
    username = db.Column(db.String(64), db.ForeignKey('user.username'), primary_key=True)
    fbid = db.Column(db.String(64), unique=True)
    about = db.Column(db.String(128))
    address = db.Column(db.String(128))
    birthday = db.Column(db.String(64))
    devices = db.Column(db.String(128))
    email = db.Column(db.String(128))
    gender = db.Column(db.String(64))
    link = db.Column(db.String(128)) #link to the person's Timeline
    location = db.Column(db.String(128)) #person's current location as entered by them
    name = db.Column(db.String(128)) #the person's full name
    timezone = db.Column(db.String(128)) #the person's current timezone
    updated_time = db.Column(db.String(128)) 
    website = db.Column(db.String(128)) #the person's website
    cover = db.Column(db.String(128)) #the person's cover photo


class FacebookPost(db.Model):
    __tablename__ = 'facebookpost'
    id = db.Column(db.Integer,nullable=False, autoincrement=True,primary_key=True)
    username = db.Column(db.String(64), db.ForeignKey('user.username'))
    fbid = db.Column(db.String(64))
    timestamp  = db.Column(db.DateTime,default=db.func.now())    
    content = db.Column(db.String(512))


class Follow(db.Model):
    __tablename__ = "follow"
    follow_from = db.Column(db.String(64), db.ForeignKey('user.username'), primary_key=True)
    follow_to = db.Column(db.String(64), db.ForeignKey('user.username'), index=True)


class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    register_timestamp = db.Column(db.DateTime, default=db.func.now())    
    group_type = db.Column(db.String(64), db.ForeignKey('grouptype.typename'))
    privacy = db.Column(db.String(64))


class GroupMember(db.Model):
    __tablename__ = 'groupmember'
    groupname = db.Column(db.Integer, db.ForeignKey('group.id'), primary_key=True)
    member = db.Column(db.Integer, db.ForeignKey('user.username'))
    job = db.Column(db.String(64))
    #member : member of the group
    #manager : manager of the group
    #block : person who is blocked from the group

class GroupType(db.Model):
    __tablename__ = "grouptype"
    typename = db.Column(db.String(64), primary_key=True)
    abouttype = db.Column(db.String(256))


class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Integer, db.ForeignKey('user.username'))
    timestamp  = db.Column(db.DateTime, default=db.func.now())
    content = db.Column(db.String(512))
    lat = db.Column(db.Integer)
    lng = db.Column(db.Integer)

    comment = db.relationship('Comment', backref='post',
                                lazy='dynamic')

    # location = db.Column(Location(64))
    tag = db.Column(Json(128))
    to = db.Column(Json(128)) #공유 대상 Json 형식 , Foreign Key 로

class Photo(db.Model):
    __tablename__ = 'photo'
    id = db.Column(db.Integer, primary_key=True)
    postid = db.Column(db.Integer, db.ForeignKey('post.id'), index=True)
    location = db.Column(Location(64))
    tag = db.Column(Json(256))
    content = db.Column(db.String(512))
    timestamp  = db.Column(db.DateTime)
    filename = db.Column(db.String(64)) 


class Movie(db.Model):
    __tablename__ = 'movie'
    id = db.Column(db.Integer, primary_key=True)
    postid = db.Column(db.Integer, db.ForeignKey('post.id'), index=True)
    location = db.Column(Location(64))
    tag = db.Column(Json(256))
    content = db.Column(db.String(512))
    timestamp  = db.Column(db.DateTime)
    filename = db.Column(db.String(64))
    filesize = db.Column(db.Integer)


class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    postid = db.Column(db.Integer,  db.ForeignKey('post.id'), index=True)
    username = db.Column(db.Integer, db.ForeignKey('user.username'))
    tag = db.Column(Json(256))
    content = db.Column(db.String(512))
    timestamp  = db.Column(db.DateTime, default=db.func.now())
    
class Event(db.Model):
    __tablename__ = 'event'
    id = db.Column(db.Integer, primary_key=True)
    postid = db.Column(db.Integer, db.ForeignKey('post.id'), index=True)
    tag = db.Column(Json(256))
    content = db.Column(db.String(512))
    timestamp  = db.Column(db.DateTime)
    timeFrom = db.Column(db.DateTime)    
    timeTo = db.Column(db.DateTime)


class Place(db.Model):
    __tablename__ = 'place'
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(Location(64))
    name = db.Column(db.String(128))
    description = db.Column(db.String(256))



if not os.path.exists('db.sqlite'):
    print 'create table'
    db.create_all()


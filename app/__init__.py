from flask import Flask
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.sqlalchemy import SQLAlchemy
from flask_s3 import FlaskS3
import redis
import os

ALLOWED_EXTENSIONS = set(['jpg','png'])

# initialization

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

if app.config['SQLALCHEMY_DATABASE_URI']==None:
	print "need database config"
	sys.exit(1)
 	

# extensions
auth = HTTPBasicAuth()
db = SQLAlchemy(app)


from app import control, models

db.create_all()


def redis_synchro():
	x = control.redis_connections.keys('prefix:*') 
	for key in x: control.redis_connections.delete(key)
	print "cache flush"
	db_user_list = models.User.query.filter_by().all()
	for each_user in db_user_list:
	    control.redis_username.append(each_user.username)
	    control.redis_password.append(each_user.password_hash)
	    print each_user.username
	print "cache updated"


redis_synchro()


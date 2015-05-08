from flask import Flask
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.sqlalchemy import SQLAlchemy
import redis
import os

UPLOAD_FOLDER = './img/'
ALLOWED_EXTENSIONS = set(['jpg','png'])

# initialization

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

if app.config['SQLALCHEMY_DATABASE_URI']==None:
	print "need database config"
	sys.exit(1)
 	

# extensions
auth = HTTPBasicAuth()
db = SQLAlchemy(app)


from app import control, models

db.create_all()


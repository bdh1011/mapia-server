from flask import Flask
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.sqlalchemy import SQLAlchemy
import redis
import os

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


db = SQLAlchemy(app)


from app import control, models

if not os.path.exists('db.sqlite'):
    print 'create table'
    db.create_all()


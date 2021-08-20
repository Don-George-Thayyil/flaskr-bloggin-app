import os
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, instance_relative_config=True)
app.config["SECRET_KEY"] = '262c27323775a67e111b8d5c6915e58d'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///site.db"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "dongeo77@gmail.com"
app.config["MAIL_PASSWORD"] = "me199887"
mail = Mail(app)

from flaskr import routes

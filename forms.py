from typing import Text
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms import validators
from wtforms.validators import DataRequired, EqualTo, Length, Email, ValidationError
from flaskr.models import User, Post
from flask_login import current_user

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(),Length(min=4, max=20)])
    email = StringField("Email", validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("This username is taken!!")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("This email is already in use!!")

class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(),Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class UpdateAccountForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(),Length(min=4, max=20)])
    email = StringField("Email", validators=[DataRequired(),Email()])
    picture = FileField('Update Pro-Pic', validators=[FileAllowed(['jpg','jpeg', 'png'])])

    submit = SubmitField("Update")

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("This username is taken!!")

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("This email is already in use!!")
    
class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    submit = SubmitField("Post")

class RequestResetForm(FlaskForm):
    email = email = StringField("Email", validators=[DataRequired(),Email()])
    submit = SubmitField("Password Request")
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError("This email is not in use!!")
        

class ResetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Reset Password")
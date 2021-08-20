from logging import log
from flask.helpers import send_file
from flaskr.models import User, Post
from flask import render_template, redirect, url_for, flash, request, abort
from flaskr.forms import RegistrationForm, LoginForm, RequestResetForm, UpdateAccountForm, PostForm, RequestResetForm, ResetPasswordForm
from flaskr import app, db, bcrypt, mail
from flask_login import login_user, current_user, logout_user, login_required
import secrets
import os
from PIL import Image
from flask_mail import Message


@app.route("/")
@app.route("/home")
@login_required
def home():
    page = request.args.get("page", default=1, type=int)
    posts = Post.query.order_by(
        Post.date_posted.desc()).paginate(per_page=4, page=page)
    return render_template("home.html", title="Home", data=posts)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for('home'))
        else:
            flash("Login failed, check your email and password!", category="danger")
    return render_template("login.html", title="Log In", data=form)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pd = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_pd)
        db.session.add(user)
        db.session.commit()
        flash(f"Account created. Please Login!!", category="success")
        return redirect(url_for('login'))
    return render_template("signup.html", title="Register", data=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


def save_picture(form_picture):
    rand_hex = secrets.token_hex(8)
    _, extension = os.path.splitext(form_picture.filename)
    file_name = rand_hex + extension
    picture_path = os.path.join(
        app.root_path, 'static/profile_pics', file_name)
    output_size = (125, 125)
    image = Image.open(form_picture)
    image.thumbnail(output_size)
    image.save(picture_path)
    return file_name


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for(
        'static', filename='profile_pics/'+current_user.image_file)
    return render_template("account.html", title="Account", image_file=image_file, data=form)


@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data,
                    content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash("Your post has been created!!", "success")
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', legend="Create Post", data=form)


@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template("post.html", title=post.title, data=post)


@app.route("/post/<int:post_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash("Your post has been updated", "success")
        return redirect(url_for("post", post_id=post.id))
    elif request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content
        return render_template('create_post.html', title='Update Post', data=form, legend="Update Post")


@app.route("/delete/<int:post_id>", methods=["GET"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash("Your post has been deleted!!", "success")
    return redirect(url_for("home"))


@app.route("/user/<string:user_name>")
@login_required
def user_posts(user_name):
    page = request.args.get("page", default=1, type=int)
    user = User.query.filter_by(username=user_name).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(per_page=4, page=page)
    return render_template("user_post.html", user=user, data=posts)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message("Password Reset Request",
                  sender="noreply@demo.com", recipients=[user.email])
    msg.body = f""" To reset your password, visit the following link:
    {url_for('reset_token', token=token, _external=True)}
    if you are not known about this action, just ignore it!!
    """
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash(f"An email has been sent with instructions to reset your password!!", "info")
        return redirect(url_for("login"))
    return render_template("reset_request.html", title="Reset Password", data=form)



@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token", 'warning')
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_pd = bcrypt.generate_password_hash(
                    form.password.data).decode('utf-8')
        user.password=hashed_pd        
        db.session.commit()
        flash(f"Password has been updated!!", category="success")
        return redirect(url_for('login'))
    return render_template("reset_token.html", title="Reset Password", data=form)

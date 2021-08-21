from flask import Blueprint, render_template, url_for, flash, redirect, request
from flaskblog import db, bcrypt
from flaskblog.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                   ResetPasswordForm, RequestResetForm, ConfirmRegister)
from flaskblog.models import User, Post
from flaskblog.users.utils import save_picture, send_reset_email, send_register_email
from flask_login import login_user, current_user, logout_user, login_required
from numpy import random

users = Blueprint('users', __name__)


@users.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        code = random.randint(1000, 1000000)
        hashed_code = bcrypt.generate_password_hash(f"{code}")
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, verify_code=hashed_code)
        db.session.add(user)
        db.session.commit()

        # Getting the same user to access the message
        user1 = User.query.filter_by(email=form.email.data).first()
        send_register_email(user1, code)

        flash('We send to you an verification email, please check your mail', 'success')
        return redirect(url_for('users.login'))
    return render_template('register.html', title='Register', form=form)


@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and user.verification:
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))


@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            pic_file = save_picture(form.picture.data)
            current_user.image_file = pic_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()

        flash('Successfully updating your data.', 'success')
        return redirect(url_for('users.account'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    img_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           img_file=img_file, form=form)


@users.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)


@users.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@users.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash("This Invalid or Expired Code", "warning")
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated successfully', 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


@users.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash("This Invalid or Expired Code", "warning")
        return redirect(url_for('users.reset_request'))
    form = ConfirmRegister()
    if form.validate_on_submit():
        if user and bcrypt.check_password_hash(user.verify_code, form.code.data):
            user.verification = True
            db.session.commit()
            flash('Your E-mail has been successfully confirmed', 'success')
            return redirect(url_for('users.login'))
    return render_template('confirm_register.html', title='Reset Password', form=form)

from flask import Blueprint, render_template, redirect, url_for, flash, request
from models import db, bcrypt, User
from flask_login import login_user, current_user, logout_user, login_required

user_bp = Blueprint('user', __name__)


@user_bp.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('user.user_login'))
    return render_template('user/signup.html')


@user_bp.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('user.user_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('user/login.html')


@user_bp.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user/dashboard.html')


@user_bp.route('/user/logout')
def logout():
    logout_user()
    return redirect(url_for('user.user_login'))

from flask import Blueprint, render_template, redirect, url_for, flash, request
from models import db, bcrypt, User
from flask_login import login_user, current_user, logout_user, login_required

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        admin = User(username=username, email=email, password=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('admin.admin_login'))
    return render_template('admin/signup.html')


@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        admin = User.query.filter_by(email=email).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            login_user(admin)
            return redirect(url_for('admin.admin_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('admin/login.html')


@admin_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')


@admin_bp.route('/admin/logout')
def logout():
    logout_user()
    return redirect(url_for('admin.admin_login'))

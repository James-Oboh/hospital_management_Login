from flask import Blueprint, render_template, redirect, url_for, flash, request
from models import db, bcrypt, User
from flask_login import login_user, current_user, logout_user, login_required

employee_bp = Blueprint('employee', __name__)


@employee_bp.route('/employee/signup', methods=['GET', 'POST'])
def employee_signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        employee = User(username=username, email=email, password=hashed_password, role='employee')
        db.session.add(employee)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('employee.employee_login'))
    return render_template('employee/signup.html')


@employee_bp.route('/employee/login', methods=['GET', 'POST'])
def employee_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        employee = User.query.filter_by(email=email).first()
        if employee and bcrypt.check_password_hash(employee.password, password):
            login_user(employee)
            return redirect(url_for('employee.employee_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('employee/login.html')


@employee_bp.route('/employee/dashboard')
@login_required
def employee_dashboard():
    return render_template('employee/dashboard.html')


@employee_bp.route('/employee/logout')
def logout():
    logout_user()
    return redirect(url_for('employee.employee_login'))

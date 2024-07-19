from flask import Flask, render_template, redirect, url_for, flash
from flask_login import login_required, logout_user

from config import Config
from models import db, bcrypt, login_manager
from routes import user_bp, admin_bp, employee_bp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'user.user_login'

app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(employee_bp)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initialize the database
        print("Database initialized!")
    app.run(debug=True)

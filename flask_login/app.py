from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

"""
A simple Flask application with user registration and login functionality.

Classes:
    User: A SQLAlchemy model representing a user.
    RegistrationForm: A FlaskForm for user registration.
    LoginForm: A FlaskForm for user login.

Functions:
    load_user(user_id): Loads a user from the database by user ID.
    register(): Handles user registration.
    login(): Handles user login.
    dashboard(): Renders the dashboard page.
    logout(): Logs out the current user.
    index(): Redirects to the dashboard if the user is authenticated, otherwise to the login page.
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database models for user registration and login functionality using SQLAlchemy. 
# The User class inherits from db.Model and UserMixin. 
# The UserMixin class provides default implementations for the methods that Flask-Login expects user objects to have.

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# The load_user function is used to reload the user object from the user ID stored in the session.
# It should return None (not raise an exception) if the ID is not valid.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# The register function handles user registration. It creates a new user object with the provided username and password,
# hashes the password using bcrypt, adds the user to the database, and commits the changes.
# It also flashes a success message and redirects the user to the login page.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# The login function handles user login. It checks if the user exists in the database and if the password is correct.
# If the login is successful, it logs in the user using the login_user function from Flask-Login and redirects to the dashboard.
# If the login is unsuccessful, it flashes an error message and renders the login page.
# The current_user variable is used to check if the user is already authenticated and redirect to the dashboard.
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            print('Login:', current_user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    print(current_user)
    return render_template('login.html', form=form)

# The dashboard function renders the dashboard page. It is decorated with the login_required decorator from Flask-Login,
# which ensures that the user is authenticated before accessing the page.
# The current_user variable is used to check if the user is authenticated and display the username on the page.
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html',)

# The logout function logs out the current user using the logout_user function from Flask-Login and redirects to the login page.
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# The index function redirects to the dashboard if the user is authenticated, otherwise to the login page.
# It is the default route for the application.
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# The main entry point for the application. It creates the database tables and runs the Flask application.
if __name__ == '__main__':
    # Create the database tables before running the application.
    with app.app_context():
        db.create_all()
    app.run(debug=True)
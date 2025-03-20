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
    Recipe: A SQLAlchemy model representing a recipe.
    Ingredient: A SQLAlchemy model representing an ingredient.
    IngredientForm: A FlaskForm for adding ingredients to a recipe.
    RecipeForm: A FlaskForm for creating a recipe.

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

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ingredients = db.relationship('Ingredient', backref='recipe', lazy=True)
    steps = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.String(100), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)

class IngredientForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    quantity = StringField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Add Ingredient')

class RecipeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    steps = StringField('Steps', validators=[DataRequired()])
    submit = SubmitField('Create Recipe')
    ingredients = db.relationship('Ingredient', backref='recipe', lazy=True)
    

# The load_user function is used to reload the user object from the user ID stored in the session.
# It should return None (not raise an exception) if the ID is not valid.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            print('Login:', current_user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    print(current_user)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    recipes = Recipe.query.all()
    return render_template('index.html', recipes=recipes)

@app.route('/new', methods=['GET', 'POST'])
@login_required
def new_recipe():
    form = RecipeForm()
    if form.validate_on_submit():
        recipe = Recipe(name=form.name.data, steps=form.steps.data, user_id=current_user.id)
        db.session.add(recipe)
        db.session.commit()
        flash('Your recipe has been created!', 'success')
        return redirect(url_for('index'))
    return render_template('create_recipe.html', form=form)

# The main entry point for the application. It creates the database tables and runs the Flask application.
if __name__ == '__main__':
    # Create the database tables before running the application.
    with app.app_context():
        db.create_all()
    app.run(debug=True)
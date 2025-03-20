from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from app import db

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class IngredientForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    quantity = StringField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Add Ingredient')

class RecipeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    steps = StringField('Steps', validators=[DataRequired()])
    submit = SubmitField('Create Recipe')
    ingredients = db.relationship('Ingredient', backref='recipe', lazy=True)
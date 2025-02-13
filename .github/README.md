# Building a simple CMS (Content Management System) with Flask

Here's a basic outline:

- Set Up Flask: Start by setting up a basic Flask application. This will include creating routes and templates.
- Create a Content Management Module: Develop a module to handle content management. This can include functions to add, edit, and delete content.
- Database Integration: Use a simple database like SQLite to store the content. You can use SQLAlchemy for ORM (Object Relational Mapping).
- User Authentication: Implement basic user authentication to manage access to the CMS.
- Templates and Forms: Use Flask-WTF for form handling and Jinja2 for templating.

## Introduction

In this tutorial, you will learn how to build a basic Content Management System (CMS) using Flask. This CMS will allow you to add, view, and manage content. We will use SQLite for the database and Flask-WTF for form handling.

## Prerequisites

- Basic knowledge of Python and Flask
- Flask installed on your system
- Familiarity with HTML and CSS

## Step 1: Set Up Your Flask Environment

1. **Install Flask and Extensions**:
   Open your terminal and run the following command to install Flask and the necessary extensions (if they are not already installed):

   ```bash
   pip install Flask Flask-SQLAlchemy Flask-WTF
   ```

2. **Create a Project Directory**:
   Create a new directory for your project and navigate into it:

   ```bash
   mkdir flask_cms
   cd flask_cms
   ```

3. **Initialize a Flask Application**:
   Create a new file named `app.py` and add the following code to set up a basic Flask application:

   ```python
   from flask import Flask, render_template, redirect, url_for, request
   from flask_sqlalchemy import SQLAlchemy

   app = Flask(__name__)
   app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cms.db'
   db = SQLAlchemy(app)

   class Content(db.Model):
       id = db.Column(db.Integer, primary_key=True)
       title = db.Column(db.String(100), nullable=False)
       body = db.Column(db.Text, nullable=False)

   @app.route('/')
   def index():
       contents = Content.query.all()
       return render_template('index.html', contents=contents)

   @app.route('/add', methods=['GET', 'POST'])
   def add():
       if request.method == 'POST':
           title = request.form['title']
           body = request.form['body']
           new_content = Content(title=title, body=body)
           db.session.add(new_content)
           db.session.commit()
           return redirect(url_for('index'))
       return render_template('add.html')

   if __name__ == '__main__':
       with app.app_context():
        db.create_all()
       app.run(debug=True)
   ```

## Step 2: Create Database Models

1. **Define the Content Model**:
   In the `app.py` file, we have already defined a `Content` model with `id`, `title`, and `body` fields. This model will be used to store the content in the database.

2. **Initialize the Database**:
   Run the following command in your terminal to create the database and the `Content` table:
   ```bash
   python app.py
   ```

## Step 3: Create Templates

1. **Create the Templates Directory**:
   Inside your project directory, create a new directory named `templates`.

2. **Create the `index.html` Template**:
   Inside the `templates` directory, create a file named `index.html` and add the following code:

   ```html
   <!DOCTYPE html>
   <html lang="en">
     <head>
       <meta charset="UTF-8" />
       <title>Content Management System</title>
     </head>
     <body>
       <h1>Content List</h1>
       <ul>
         {% for content in contents %}
         <li>{{ content.title }}</li>
         {% endfor %}
       </ul>
       <a href="{{ url_for('add') }}">Add New Content</a>
     </body>
   </html>
   ```

3. **Create the `add.html` Template**:
   Inside the `templates` directory, create a file named `add.html` and add the following code:
   ```html
   <!DOCTYPE html>
   <html lang="en">
     <head>
       <meta charset="UTF-8" />
       <title>Add Content</title>
     </head>
     <body>
       <h1>Add New Content</h1>
       <form method="POST">
         <label for="title">Title:</label>
         <input type="text" name="title" id="title" />
         <label for="body">Body:</label>
         <textarea name="body" id="body"></textarea>
         <button type="submit">Add</button>
       </form>
     </body>
   </html>
   ```

## Step 4: Run the Application

1. **Start the Flask Application**:
   Run the following command in your terminal to start the Flask application:

   ```bash
   python app.py
   ```

2. **Access the Application**:
   Open your web browser and navigate to `http://127.0.0.1:5000/`. You should see the content list and a link to add new content.

## Conclusion

Congratulations! You have successfully built a simple CMS using Flask. You can expand this project by adding features like editing and deleting content, user authentication, and more.

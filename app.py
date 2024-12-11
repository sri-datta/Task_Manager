from flask import Flask, render_template, request, redirect, jsonify,url_for,session,flash
# from authlib.integrations.flask.client import OAuth
import pymysql
from authlib.integrations.flask_client import OAuth
import openai
import ssl
import socket
import bcrypt
import requests
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from wtforms import Form, StringField, TextAreaField, DateField, BooleanField, validators
from flask_caching import Cache
from flask_swagger_ui import get_swaggerui_blueprint
from openai import OpenAI

# Initialize OpenAI client
client = OpenAI(api_key="") #replace your api key
def generate_schedule(tasks, role, goal):
    # Instruction for the AI to generate a schedule
    instruct = (
        f"Please create a detailed schedule with timestamps for a {role} whose goal for the day is '{goal}'. "
        f"Ensure all tasks from the provided list are included, balanced throughout the day, and appropriately aligned with the goal '{goal}'. "
        f"Add meaningful breaks and suggest activities (not exceeding 1 hour) that can enhance the productivity or well-being of a {role}. "
        f"Format: 'Time - Task description'. Fix any spelling mistakes you find. Just give me the schedule and nothing else. No explanation, nothing. "
        f"Make sure the schedule reflects the best practices for a {role} with the goal '{goal}' while retaining all provided tasks."
    )
    
    # Combine tasks and the instruction into the prompt
    prompt = tasks + "\n\n" + instruct

    try:
        # Call OpenAI API for generating the schedule
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an assistant that generates schedules."},
                {"role": "user", "content": prompt}
            ]
        )

        # Extract and clean the schedule from the response
        schedule = completion.choices[0].message.content.strip()
        return schedule
    except Exception as e:
        print(f"Error generating schedule: {e}")
        return "Failed to generate schedule. Please try again."

app = Flask(__name__)
app.secret_key = '720121a9e63ae0f982894dd2260a5391faf83b5ef5119b65'


@app.before_request
def log_request_info():
    app.logger.info(f"Request received on server: {socket.gethostname()} | URL: {request.url}")

#Cache Configuration
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_URL'] = 'redis://localhost:6379/0'

# Initialize Cache
cache = Cache(app)

# Suppress SSL certificate verification warnings
requests.packages.urllib3.disable_warnings()

# Override SSL context creation to disable certificate verification
ssl._create_default_https_context = ssl._create_unverified_context

oauth = OAuth(app)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id='',  # Replace with your Google Client ID
    client_secret='',  # Replace with your Google Client Secret
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent',  # Add this for consent screen prompt
    }
)


google.redirect_uri = 'http://localhost:5000/authorize'


# MySQL Configuration
# Replace Your Database Config

app.config['MYSQL_HOST'] = ''
app.config['MYSQL_USER'] = ''
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = ''
app.config['MYSQL_PORT'] = 




db = pymysql.connect(host=app.config['MYSQL_HOST'],
                     user=app.config['MYSQL_USER'],
                     password=app.config['MYSQL_PASSWORD'],
                     db=app.config['MYSQL_DB'],
                     charset='utf8mb4',
                     cursorclass=pymysql.cursors.DictCursor)


cursor = db.cursor()


# TaskForm definition
class TaskForm(Form):
    title = StringField('Title', validators=[validators.DataRequired()])
    description = TextAreaField('Description')
    due_date = DateField('Due Date', format='%Y-%m-%d', validators=[validators.DataRequired()])


class Task:
    def __init__(self, id, title, description, due_date, completed,user_id):
        self.id = id
        self.title = title
        self.description = description
        self.due_date = due_date
        self.completed = completed
        self.user_id = user_id

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            # Redirect to the login page if the user is not logged in
            return redirect(url_for('custom_login'))
        return f(*args, **kwargs)
    return decorated_function

def create_task(title, description, due_date,user_id):
    print(user_id)
    sql = "INSERT INTO tasks_new (title, description, due_date,user_id) VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (title, description, due_date,user_id))
    db.commit()



def get_tasks(user_id):
    sql = "SELECT * FROM tasks_new WHERE user_id = %s"
    cursor.execute(sql,(user_id,))
    tasks = []
    for row in cursor.fetchall():
        task = Task(row['id'], row['title'], row['description'], row['due_date'], row['completed'], row['user_id'])
        tasks.append(task)
    return tasks

def get_task_by_id_from_database(task_id):
    sql = "SELECT * FROM tasks_new WHERE id = %s"
    cursor.execute(sql, (task_id,))
    row = cursor.fetchone()

    if row:
        task = Task(row['id'], row['title'], row['description'], row['due_date'], row['completed'])
        return task
    else:
        return None


def update_task(task_id, title, description, due_date, completed):
    sql = "UPDATE tasks_new SET title=%s, description=%s, due_date=%s, completed=%s WHERE id=%s"
    cursor.execute(sql, (title, description, due_date, completed, task_id))
    db.commit()

# Function to create a user in the database
def create_users(email, password, user_name):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    print(user_name)
    print(email)
    print(hashed_password)
    sql = "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
    cursor.execute(sql, (user_name, email, hashed_password))
    db.commit()

    user_id = cursor.lastrowid
    return user_id


# Function to get user information from the database
def get_user(email):
    sql = "SELECT * FROM users WHERE email = %s"
    cursor.execute(sql, (email,))
    return cursor.fetchone()

def get_all_users():
    try:
        sql = "SELECT id, username, email FROM users"
        cursor.execute(sql)
        users = cursor.fetchall()
        print("Retrieving users from the database...")
        return users
    except Exception as e:
        return []
    
def get_username(email):
    sql = "SELECT username FROM users WHERE email = %s"
    cursor.execute(sql, (email,))
    user = cursor.fetchone()
    if len(user) != 0:
        # Extract the username from the result
        return user['username']
    else:
        return None


def verify_user(email, password):
    user = get_user(email)
    if user:
        hashed_password = user['password_hash']
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return True
        else:
            print("Password Mismatch!")
            return False


# Routes
    
#GET

@app.route('/', methods=['GET'])
@login_required
def home():
    # Redirect to the dashboard of the logged-in user
    if 'user_id' in session:
        return redirect(url_for('dashboard', user_id=session['user_id']))
    return redirect(url_for('custom_login'))


@app.route('/dashboard/<int:user_id>/', methods=['GET'])
@login_required
def dashboard(user_id):
    # Check if the user is logged in
    if 'email' not in session:
        print("User not logged in, redirecting to login page...")
        return redirect(url_for('custom_login'))
    
    # Retrieve user name from the session
    user_name = session.get('user_name')
    return render_template('dashboard.html', user_id=user_id, user_name=user_name)


@app.route('/dashboard/<int:user_id>/tasks', methods=['GET'])
def index(user_id):
    print("Entering index route...")
    
    # Check if the user is logged in
    if 'email' not in session:
        print("User not logged in, redirecting to login page...")
        return redirect(url_for('custom_login'))
    
    # Retrieve session details
    email = dict(session).get('email', None)
    user_name = session.get('user_name')
    print(f"User ID: {user_id}")
    
    # Check the cache for tasks
    cached_tasks = cache.get(f'/tasks/{user_id}')
    if cached_tasks:
        print("Retrieved tasks from cache")
        tasks = cached_tasks
    else:
        # Fetch tasks from the database
        tasks = get_tasks(user_id)
        print("Tasks retrieved from the database.")
        cache.set(f'/tasks/{user_id}', tasks)
    
    for task in tasks:
        print(task.title)
    
    # Render the tasks page
    return render_template('index.html', user_id=user_id, tasks=tasks, email=email, user_name=user_name)


@app.route('/custom_login', methods=['GET', 'POST'])
def custom_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        print(email)
        print(password)
        if email == 'admin@gmail.com' and password == 'Admin@123':
            # Redirect to admin portal if the user is admin
            session['email'] = email
            session['user_name'] = get_username(email)
            session['user_id'] = get_user(email)['id']
            return redirect(url_for('admin_portal'))
        elif verify_user(email, password):
            # Redirect to index page for non-admin users
            session['email'] = email
            session['user_name'] = get_username(email)
            session['user_id'] = get_user(email)['id']
            return redirect(url_for('dashboard', user_id=session.get('user_id')))
        else:
            # Authentication failed, redirect to login page with error message
            return render_template('login.html', error='Invalid email or password')
    else:
        # Render login page for GET request
        return render_template('login.html')




@app.route('/admin_portal')
@cache.cached(timeout=60)
def admin_portal():
    email = session.get('email')
    user_name = session.get('user_name')
    users = get_all_users()  # Function to get all users from the database
    return render_template('admin_portal.html', email=email, user_name=user_name, users=users)


@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)



@app.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    # Redirect to the login page or any other page after logout
    return redirect(url_for('custom_login'))

@app.route('/create_user', methods=['GET'])
def create_user_form():
    return render_template('create_user.html')

@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    
    # Check if the user already exists
    existing_user = get_user(email)
    if existing_user:
        return render_template('create_user.html', error='User already exists')
    
    # Create the user
    create_users(email,password,username)
    
    # Redirect to the login page
    return redirect(url_for('custom_login'))

@app.route('/authorize')
def authorize():
    # Exchange the authorization code for an access token
    token = google.authorize_access_token()
    
    # Fetch user info from Google
    user_info = google.get('userinfo').json()
    session['email'] = user_info.get('email')
    session['user_name'] = user_info.get('name')
    
    # Check if the user exists in the database or create a new user
    email = session['email']
    username = session['user_name']
    user = get_user(email)
    if user:
        # User exists, store user_id in session
        session['user_id'] = user['id']
    else:
        # Create a new user
        user_id = create_users(email, 'default_password', username)
        session['user_id'] = user_id

    # Redirect to the user's dashboard
    return redirect(url_for('dashboard', user_id=session['user_id']))





#POST
@app.route('/dashboard/<int:user_id>/tasks/add_task', methods=['GET', 'POST'])
@login_required
def add_task(user_id):
    print("Entering add_task route...")
    if request.method == 'POST':
        print("Received a POST request to add a task")
        form = TaskForm(request.form)
        if form.validate():
            title = form.title.data
            description = form.description.data
            due_date = form.due_date.data
            user_id = session.get('user_id')
            print(f"User ID: {user_id}")
            create_task(title, description, due_date, user_id)
            print("Task created.")
            print("Before cache deletion")
            tasks = get_tasks(session.get('user_id'))
            cache.set(f'/tasks/{user_id}', tasks)
            cache.delete_memoized(index)  # Delete memoized cache for index function
            print("After cache deletion")
            return redirect(url_for('index', user_id=user_id))
        else:
            return render_template('add_task.html',user_id=user_id, form=form)
    else:
        print("Rendering add task form for GET request")
        form = TaskForm()
        return render_template('add_task.html',user_id=user_id, form=form)



#PUT
@app.route('/dashboard/<int:user_id>/tasks/update_task/<int:task_id>', methods=['PUT'])
@login_required
def update_task_route(user_id, task_id):
    form = TaskForm(request.form)
    if form.validate():
        title = form.title.data
        description = form.description.data
        due_date = form.due_date.data
        completed = 'completed' in request.form
        update_task(task_id, title, description, due_date, completed)
        user_id = session.get('user_id')
        tasks = get_tasks(user_id)
        cache.set(f'/tasks/{user_id}', tasks)  # Update cache with the updated tasks
        cache.delete_memoized(index) 
        return jsonify({"message": "Task updated successfully"})
    else:
        return jsonify({"error": "Validation failed"}), 400


#DELETE 
@app.route('/dashboard/<int:user_id>/tasks/delete_task/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(user_id,task_id):
    if request.method == 'DELETE':
        print("Received a DELETE request to delete task with ID:", task_id)
        try:
            # Perform deletion logic here
            sql = "DELETE FROM tasks_new WHERE id = %s"
            cursor.execute(sql, (task_id,))
            db.commit()
            user_id = session.get('user_id')
            tasks = get_tasks(user_id)
            cache.set(f'/tasks/{user_id}', tasks)  # Update cache with the updated tasks
            cache.delete_memoized(index) 
            return jsonify({"message": "Task deleted successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        # If the request method is not DELETE, return a Method Not Allowed error
        return jsonify({"error": "Method Not Allowed"}), 405
    

@app.route('/dashboard/<int:user_id>/plan_day', methods=['GET', 'POST'])
@login_required
def plan_day(user_id):
    if request.method == 'POST':
        # Retrieve tasks, role, and goal from the form
        tasks = request.form.get('tasks')
        role = request.form.get('profile')  # Retrieve the selected role
        goal = request.form.get('goal')    # Retrieve the selected goal
        print(f"Tasks: {tasks}, Role: {role}, Goal: {goal}")

        if tasks and role and goal:
            # Call OpenAI API to generate the schedule
            schedule = generate_schedule(tasks, role, goal)  # Pass tasks, role, and goal to the function
            return render_template('plan_day.html', user_id=user_id, schedule=schedule, tasks=tasks, role=role, goal=goal)
        else:
            flash("Please enter your tasks, select your role, and choose your goal.", "warning")
            return redirect(url_for('plan_day', user_id=user_id))

    return render_template('plan_day.html', user_id=user_id, tasks='', schedule='', role='', goal='')


   



# Swagger
SWAGGER_URL = '/swagger'
API_URL = '/swagger.json'


swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Todo Application"
    }
)


app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/swagger.json')
def swagger_spec():
    spec = {
        "swagger": "2.0",
        "info": {
            "title": "Todo Application API",
            "description": "API for managing tasks in a todo application",
            "version": "1.0"
        },
        "paths": {
            "/add_task": {
                "post": {
                    "summary": "Add a new task",
                    "parameters": [
                        {
                            "name": "title",
                            "in": "formData",
                            "description": "Title of the task",
                            "required": True,
                            "type": "string"
                        },
                        {
                            "name": "description",
                            "in": "formData",
                            "description": "Description of the task",
                            "required": False,
                            "type": "string"
                        },
                        {
                            "name": "due_date",
                            "in": "formData",
                            "description": "Due date of the task (format: YYYY-MM-DD)",
                            "required": True,
                            "type": "string",
                            "format": "date"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Task added successfully"
                        },
                        "400": {
                            "description": "Validation failed"
                        }
                    }
                }
            },
            "/update_task/{task_id}": {
                "put": {
                    "summary": "Update an existing task",
                    "parameters": [
                        {
                            "name": "task_id",
                            "in": "path",
                            "description": "ID of the task to update",
                            "required": True,
                            "type": "integer"
                        },
                        {
                            "name": "title",
                            "in": "formData",
                            "description": "New title of the task",
                            "required": True,
                            "type": "string"
                        },
                        {
                            "name": "description",
                            "in": "formData",
                            "description": "New description of the task",
                            "required": False,
                            "type": "string"
                        },
                        {
                            "name": "due_date",
                            "in": "formData",
                            "description": "New due date of the task (format: YYYY-MM-DD)",
                            "required": True,
                            "type": "string",
                            "format": "date"
                        },
                        {
                            "name": "completed",
                            "in": "formData",
                            "description": "Whether the task is completed",
                            "required": False,
                            "type": "boolean"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Task updated successfully"
                        },
                        "400": {
                            "description": "Validation failed"
                        }
                    }
                }
            },
            "/delete_task/{task_id}": {
                "delete": {
                    "summary": "Delete a task",
                    "parameters": [
                        {
                            "name": "task_id",
                            "in": "path",
                            "description": "ID of the task to delete",
                            "required": True,
                            "type": "integer"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Task deleted successfully"
                        },
                        "404": {
                            "description": "Task not found"
                        }
                    }
                }
            },
            "/": {
                "get": {
                    "summary": "Get all tasks",
                    "responses": {
                        "200": {
                            "description": "Tasks retrieved successfully"
                        }
                    }
                }
            }
        }
    }

    return jsonify(spec)



if __name__ == '__main__':
    # Run the Flask app on localhost:5000
    app.run(debug=True, port=5000)

    # Create a second instance of the Flask app to run on localhost:5001
    app.config['SERVER_NAME'] = 'localhost:5001'
    app.run(debug=True, port=5001)


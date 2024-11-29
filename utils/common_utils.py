from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            # Redirect to the login page if the user is not logged in
            return redirect(url_for('custom_login'))
        return f(*args, **kwargs)
    return decorated_function

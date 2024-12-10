from flask import Flask, render_template, request, redirect, url_for, session
import os
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load predefined users and hashed passwords from environment variables or a secure source
users = {
    "admin": bcrypt.hashpw(b"default_admin_password", bcrypt.gensalt()),
    "user1": bcrypt.hashpw(b"default_user1_password", bcrypt.gensalt())
}

login_requests = []

# Utility function to validate login credentials
def check_login(username, password):
    stored_hash = users.get(username)
    return stored_hash and bcrypt.checkpw(password.encode(), stored_hash)

@app.route('/')
def index():
    return render_template('index.html', error=None, request_message=None)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if check_login(username, password):
        session['admin_logged_in'] = True
        return redirect(url_for('admin_dashboard'))
    return render_template('index.html', error="Invalid login credentials.")

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html', login_requests=login_requests or [])

@app.route('/approve_request/<username>')
def approve_request(username):
    if username in login_requests:
        login_requests.remove(username)
        users[username] = bcrypt.hashpw(b"defaultpassword", bcrypt.gensalt())
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_request/<username>')
def reject_request(username):
    login_requests[:] = [user for user in login_requests if user != username]
    return redirect(url_for('admin_dashboard'))

@app.route('/request_login', methods=['POST'])
def request_login():
    username = request.form.get('username')

    if username not in users and username not in login_requests:
        login_requests.append(username)
        message = "Your login request has been submitted for admin approval."
    else:
        message = "This username already exists or is pending approval."
    return render_template('index.html', request_message=message)

if __name__ == '__main__':
    app.run(debug=True)



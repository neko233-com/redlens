from flask import Flask, request, render_template_string, redirect
import os

app = Flask(__name__)

USERS = {
    "admin": "admin",
    "root": "password",
    "test": "123456"
}

@app.route('/')
def index():
    return '''
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
    <h1>Vulnerable Test Application</h1>
    <p>This app is intentionally vulnerable for redlens testing.</p>
    <ul>
    <li><a href="/login">Login</a></li>
    <li><a href="/search">Search</a></li>
    <li><a href="/admin">Admin Panel</a></li>
    <li><a href="/files">Files</a></li>
    </ul>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username in USERS and USERS[username] == password:
            return f'<h1>Welcome {username}!</h1><p>You are logged in.</p>'
        return '<h1>Login Failed</h1><p>Invalid credentials.</p>'
    return '''
    <form method="post">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Password"><br>
    <button type="submit">Login</button>
    </form>
    '''

@app.route('/search')
def search():
    q = request.args.get('q', '')
    return f'<h1>Search Results</h1><p>You searched for: {q}</p>'

@app.route('/admin')
def admin():
    return '<h1>Admin Panel</h1><p>Welcome to admin panel.</p>'

@app.route('/files')
def files():
    files_list = os.listdir('.')
    return '<h1>Files</h1><ul>' + ''.join(f'<li>{f}</li>' for f in files_list) + '</ul>'

@app.route('/env')
def env():
    return '<h1>Environment</h1><pre>' + str(dict(os.environ)) + '</pre>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

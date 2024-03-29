from flask import Flask, render_template, request, flash, url_for, redirect, session
from functools import wraps
from flask_pymongo import PyMongo
from passlib.hash import sha256_crypt

import pyotp

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'data_login'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/data_login'
mongo = PyMongo(app)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get Form fields
        username = request.form['username']
        password = request.form['password']
        user = mongo.db.users
        u = user.find({'username': username})
        arr_user = []
        for user in u:
            arr_user.append(user)
        if u.count() > 0:
            pass_db = str(arr_user[0]['password'])
            if sha256_crypt.verify(password,pass_db):
                session['username'] = username
                session['email'] = arr_user[0]['email']
                session['key_otp'] = arr_user[0]['key_otp']
                session['logged_in'] = True
                flash('Login user and password success'+str(arr_user[0]['password']), 'success')
                return redirect(url_for('otp'))
            error = 'Password incorrect'
            return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error = error)

    return render_template('login.html')
# Check login

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        flash('Unauthorized, Please login', 'danger')
        return redirect(url_for('login'))
    return wrap
# Check otp
def is_verify_otp(f):
    @wraps(f)
    def wrap_otp(*args, **kwargs):
        if 'verify_otp' in session and 'logged_in' in session:
            return f(*args, **kwargs)
        flash('Unauthorized, Please login and Check otp', 'danger')
        return redirect(url_for('login'))
    return wrap_otp

@app.route('/otp', methods = ['GET', 'POST'])
@is_logged_in
def otp():
    if request.method == 'POST':
        data_qr = request.form['data_qr']
        code_otp = request.form['code_otp']
        otp_totp = pyotp.TOTP(code_otp)

        if data_qr == otp_totp.now():
            session['verify_otp'] = True
            flash("verify code success", 'success')
            return redirect(url_for('dashboard'))
        create_qr = request.form['create_qr']
        error = "code OTP incorrect!"
        return  render_template('otp.html', error = error, secret_key = code_otp)
    # Create OTP
    secret_key = session['key_otp']
    create_qr = pyotp.totp.TOTP(secret_key).provisioning_uri(session['email'], issuer_name = "Login 2 step")
    return render_template('otp.html', secret_key = secret_key)

@app.route('/dashboard')
@is_verify_otp
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug = True)

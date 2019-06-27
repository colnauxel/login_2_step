from flask import Flask, render_template, request, flash, url_for, redirect, session
from functools import wraps
from flask_pymongo import PyMongo
import pyotp

from wtforms import Form,StringField
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
        u = user.find({'username': username, 'password': password}).count()

        if u > 0:
            session['username'] = username
            session['logged_in'] = True
            flash('Login user and password success', 'success')
            return redirect(url_for('otp'))
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
        if data_qr == code_otp:
            session['verify_otp'] = True
            flash("verify code success", 'success')
            return redirect(url_for('dashboard'))
        error = "code OTP incorrect!"
        return  render_template('otp.html', error = error)
    # Create OTP
    secret_key = pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    return render_template('otp.html', totp = totp.now())

@app.route('/dashboard')
@is_verify_otp
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)






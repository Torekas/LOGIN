from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
import hashlib
import binascii
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user, fresh_login_required
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_massage = 'First, please log in using this form:'
login_manager.refresh_view = 'login'
login_manager.refresh_message = 'You need to log on again'

class User(db.Model, UserMixin):
    name = db.Column(db.String(50), primary_key = True)
    password = db.Column(db.String(100))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))

    def __repr__(self):
        return ('User: {},{}'.format(self.name))

    def get_id(self):
        return self.name

    def get_hashed_password(password):
        "Hash a password for storing"
        os_urandom_static = b'\x0b\xd8\xdd\x03\x1a2yYP\xb8)\x9c\xbe \xf1A\x16D|\x87\x078\xb6\xacm\xca\xf4B\xb9\x9d\x04>x\xceM4-\x1b\xdc\xb8\x16\x8a\x93ff\xe0\xc7\x84\xbb\xc6\xef\xaa\x00\x9bJ\xab]/\xb6\xac'
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(stored_password_hash, provided_password):
        """Verify password againsts one provided user"""
        salt = stored_password_hash[:64]
        stored_password = stored_password_hash[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

@login_manager.user_loader
def load_user(name):
    return User.query.filter(User.name == name).first()

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url,target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

class LoginForm(FlaskForm):
    name = StringField('User name')
    password = PasswordField('Password')
    remember = BooleanField('Remember me')

@app.route('/init')
def init():
    db.create_all()

    admin = User.query.filter(User.name=='admin').first()
    if admin == None:
        admin = User( name='admin', password=User.get_hashed_password('Password'),
                     first_name='King', last_name='Kong')
        db.session.add(admin)
        db.session.commit()
    return '<h1>Initial configuration done!</h1>'

@app.route('/')
def index():
    return '<h1>Hello!</h1>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter(User.name == form.name.data).first()
        if user != None and User.verify_password(user.password, form.password.data):
            login_user(user, remember=form.remember.data)

            next = request.args.get('next')

            if next and is_safe_url(next):
                return redirect(next)
            else:
                return '<h1>You are authenticated</h1>'

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return '<h1>You are logged out</h>'

@app.route('/docs')
@login_required
def docs():
    return '<h1>You have access to protected docs</h>'

@app.route('/secrets')
@fresh_login_required
def secrets():
    return '<h1> You have access to protected secretes</h1>'

if __name__ == '__main__':
    app.run()

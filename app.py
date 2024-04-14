import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret-key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=True)  # Store the public key
    certificate = db.Column(db.LargeBinary, nullable=True)  # Store the certificate
    private_key = db.Column(db.LargeBinary, nullable=True)  # Encrypted private key storage
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    group = db.relationship('Group', backref='users')
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('messages', lazy=True))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_messages', lazy=True))

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')
    
# Initialize database within an application context
with app.app_context():
    db.drop_all()
    db.create_all()

@app.route('/')
def home():
    return "Welcome to the Secure Social Network!"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        private_key, public_key, certificate = generate_keys_and_certificate()
        new_user = User(
            username=form.username.data, 
            password=hashed_password, 
            public_key=public_key,
            private_key=private_key, 
            certificate=certificate
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Automatically create a secure group for each new user
        new_group = Group(name=f"{new_user.username}'s Secure Group")
        new_group.users.append(new_user)  # Add the user to their own group
        db.session.add(new_group)
        db.session.commit()
        
        flash('New user has been created!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Get the secure group for the current user
    secure_group = current_user.group
    members = list(secure_group.users) if secure_group else []

    if request.method == 'POST':
        # Check what type of action is being requested
        action = request.form.get('action', '')

        if action == 'send_message':
            message_content = request.form['message']
            
           # Encrypt the message for each group member
            encrypted_messages = encrypt_message_for_group(message_content, members)
            
            # Save encrypted messages for each member
            for member_id, encrypted_message in encrypted_messages.items():
                new_message = Message(content=encrypted_message, sender_id=current_user.id, recipient_id=member_id)
                db.session.add(new_message)
            
            db.session.commit()
            flash('Your message has been posted!')

        elif action == 'add_user':
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            if user and secure_group and user not in secure_group.users:
                secure_group.users.append(user)
                db.session.commit()
                flash('User added to group!')
            else:
                flash('User or group not found or user already in group!')

        elif action == 'remove_user':
            username = request.form['username']
            user = User.query.filter_by(username=username).first()
            if user and secure_group and user in secure_group.users:
                secure_group.users.remove(user)
                db.session.commit()
                flash('User removed from group!')
            else:
                flash('User or group not found or user not in group!')

    messages = Message.query.order_by(Message.timestamp.desc()).all()
    display_messages = []
    private_key = decrypt_private_key(current_user.private_key, b'my_password')
    all_recipients = [message.recipient_id for message in messages]

    for message in messages:
        if current_user.id in all_recipients:
            if message.recipient_id == current_user.id:
                # User is in the secure group, decrypt the message
                decrypted_message = decrypt_message(message.content, private_key)  # Adjust with actual decryption logic
                display_messages.append((message, decrypted_message))
        else:
            # User not in the secure group, show encrypted message
            display_messages.append((message, message.content))
            
    all_users = User.query.all()  # for the dropdown menu
    return render_template('dashboard.html', members=members, secure_group=secure_group, messages=display_messages, all_users=all_users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def generate_keys_and_certificate():
    # Generate key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'my_password')  # Use a secure method to handle this password
    )
    public_key = private_key.public_key()

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyApp"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"myapp.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    # Serialize keys and certificate
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)

    return pem_private_key, pem_public_key, pem_cert

def encrypt_message_for_group(message, group_members):
    encrypted_messages = {}
    for member in group_members:
        recipient_cert = member.certificate
        cert = x509.load_pem_x509_certificate(recipient_cert)
        public_key = cert.public_key()
        encrypted_message = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_messages[member.id] = encrypted_message
    return encrypted_messages

def decrypt_message(encrypted_message, private_key):
    # Decrypt the message using the private key
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def encrypt_private_key(private_key, password):
    # Generate a strong key from the password
    kdf = Scrypt(
        salt=os.urandom(16),
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Encrypt the private key using the derived key
    f = Fernet(base64.urlsafe_b64encode(key))
    encrypted_key = f.encrypt(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    return encrypted_key

def decrypt_private_key(encrypted_private_key, password):
    return serialization.load_pem_private_key(
        encrypted_private_key,
        password=password,
        backend=default_backend()
    )

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
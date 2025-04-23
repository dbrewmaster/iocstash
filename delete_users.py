from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Setup app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the same User model as in portal.py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(255), nullable=False)

emails_to_delete = [
    "somaharsha71@gmail.com",
    "sharshavardhan@hawk.iit.edu",
    "hsoma@databrew-llc.com",
    "somaharsha965@gmail.com",
    "somarajitha1980@gmail.com",
    "somarajitha0@gmail.com",
    "somasrinivas1973@gmail.com",
    "sharshasoma@gmail.com"
]

# Delete logic
with app.app_context():
    for email in emails_to_delete:
        user = User.query.filter_by(email=email).first()
        if user:
            db.session.delete(user)
            print(f"[✔] Deleted {email}")
        else:
            print(f"[✘] User not found: {email}")
    db.session.commit()
    print("[✔] Deletion complete.")

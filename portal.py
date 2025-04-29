from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask import request
from flask_apscheduler import APScheduler
import requests
import pytz
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
import csv
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from sqlalchemy import func
from datetime import datetime
import subprocess
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask import flash
from sqlalchemy.orm.exc import NoResultFound

# Initialize the Flask application
app = Flask(__name__)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)


# Google OAuth Configuration
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "590471980283-au7aeb65jnq31kdvgksq00eramvfou8d.apps.googleusercontent.com"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "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"

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="google.authorized",
    storage=None
)


app.register_blueprint(google_bp, url_prefix="/login")


# Secret key for session management
app.secret_key = 'your_secret_key'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'somaharsha71@gmail.com'
app.config['MAIL_PASSWORD'] = 'dtgp djyz ukup tmmv'
mail = Mail(app)

# Scheduler Configuration
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)

# IOC Scheduler Task: Runs every 60 seconds
@scheduler.task('interval', id='update_ioc_task', seconds=60, misfire_grace_time=30)
def scheduled_ioc_update():
    with app.app_context():  # <-- FIXED: wrap all DB-related work
        print("[DEBUG] Scheduled IOC update triggered")
        print("[Scheduler] Updating IOC...")
        try:
            subprocess.Popen(["python3", "threat.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            update_ioc()
            print("[⏰] update_ioc() called at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            print(f"[Scheduler Error] {e}")

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(255), nullable=False)

class IoC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(50), nullable=True)
    value = db.Column(db.String(256), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    threat_category = db.Column(db.String(100), nullable=True)
    date = db.Column(db.String(50), nullable=True)

with app.app_context():
    db.create_all()

def update_ioc(csv_filepath='iocs_combined.csv'):
    if not os.path.exists(csv_filepath):
        print(f"CSV file '{csv_filepath}' not found.")
        return

    try:
        with open(csv_filepath, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            ioc_rows = list(reader)
        print(f"[DEBUG] Loaded {len(ioc_rows)} IOCs from CSV")
    except Exception as e:
        print(f"Error reading IOC CSV: {e}")
        return

    try:
        num_deleted = db.session.query(IoC).delete()  # <-- RAW SQL deletion
        db.session.commit()
        print(f"[✔] Deleted {num_deleted} old IOCs")
    except Exception as e:
        db.session.rollback()
        print(f"[!] Error clearing existing IoC records: {e}")
        print(f"[✔] Inserting {len(ioc_rows)} new IOCs...")
        print(f"[✔] Total IOCs after update: {IoC.query.count()}")

    try:
        for row in ioc_rows:
            new_ioc = IoC(
                ioc_type=row.get("Type"),
                value=row.get("Value"),
                source=row.get("Source"),
                threat_category=row.get("Threat_Category"),
                date=row.get("Date")
            )
            db.session.add(new_ioc)
        db.session.commit()
        print("IOC data updated successfully.")
    except Exception as e:
        db.session.rollback()
        print(f"Error updating IOC data: {e}")


def get_geo_info(ip):
    try:
        # Try ipapi.co
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        data = response.json()
        print(f"[GeoInfo ipapi.co] {data}")

        region = data.get("region") or "Region Not Available"
        country = data.get("country_name") or "Country Not Available"
        timezone = data.get("timezone") or "UTC"

        if region != "Region Not Available" and country != "Country Not Available":
            return region, country, timezone

        # Fallback to ipwho.is
        response = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        data = response.json()
        print(f"[GeoInfo ipwho.is] {data}")

        region = data.get("region") or "Region Not Available"
        country = data.get("country") or "Country Not Available"
        timezone = data.get("timezone", {}).get("id", "UTC")

        return region, country, timezone

    except Exception as e:
        print(f"[GeoInfo Error] {e}")
        return "Region Not Available", "Country Not Available", "UTC"



def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    # Redirect to dashboard if already logged in
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = username
            subprocess.run(["python", "threat.py"])
            update_ioc()
            return redirect(url_for('dashboard'))
        else:
            return "Invalid Credentials", 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        

        if User.query.filter_by(username=username).first():
            return "Username already exists!", 400

        try:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                email=email,
                first_name=first_name,
                last_name=last_name,
                address="Not Provided"
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            return "Email or username already exists!", 400

    return render_template('register.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return redirect(url_for('login'))

    #  Get IP & Geo Info
    ip_address = get_client_ip()
    print(f"[DEBUG] IP Address: {ip_address}")
    region, country, user_timezone = get_geo_info(ip_address)
    print(f"[DEBUG] Geo Info: Region={region}, Country={country}, Timezone={user_timezone}")
    print(f"[LOGIN INFO] IP: {ip_address}, Region: {region}, Country: {country}")


    try:
        tz = pytz.timezone(user_timezone)
    except Exception as e:
        print(f"[Timezone Error] {e}")
        tz = pytz.utc  # fallback if invalid timezone

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400
        filepath = os.path.join('uploads', file.filename)
        file.save(filepath)
        send_email(user.email, filepath)
        return "File uploaded and emailed successfully"


    ioc_keyword = request.args.get('ioc_keyword', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 10

    ioc_query = IoC.query
    if ioc_keyword:
        ioc_query = ioc_query.filter(IoC.value.ilike(f'%{ioc_keyword}%'))

    total_iocs = ioc_query.count()
    ioc_pagination = ioc_query.paginate(page=page, per_page=per_page, error_out=False)
    ioc_list = ioc_pagination.items
    types_count = db.session.query(IoC.ioc_type, func.count(IoC.id)).group_by(IoC.ioc_type).all()
    source_counts = db.session.query(IoC.source, func.count(IoC.id)).group_by(IoC.source).all()

    return render_template(
        'dashboard.html',
        username=user.username,
        user_details=user,
        current_time=current_time,
        ioc_list=ioc_list,
        total_iocs=total_iocs,
        types_count=types_count,
        source_counts=source_counts,
        ioc_keyword=ioc_keyword,
        pagination=ioc_pagination,
        user_region=region,
        user_country=country
    )

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(user.password, current_password):
            return "Current password is incorrect", 400
        if new_password != confirm_password:
            return "New passwords do not match", 400

        user.password = generate_password_hash(new_password)
        db.session.commit()
        return "Password changed successfully"

    return render_template('change_password.html')

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    user_info = resp.json()
    email = user_info.get("email")
    if not email:
        flash("Email not available from Google.", category="error")
        return False

    user = User.query.filter_by(email=email).first()
    if user:
        session["username"] = user.username
        subprocess.run(["python", "threat.py"])
        update_ioc()
        return redirect(url_for("dashboard"))

    # NEW USER → Redirect to complete-profile
    session["pending_email"] = email
    session["pending_username"] = email.split("@")[0]
    return redirect(url_for("complete_profile"))


@app.route('/complete-profile', methods=['GET', 'POST'])
def complete_profile():
    if 'pending_email' not in session or 'pending_username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_user = User(
            username=session["pending_username"],
            password=generate_password_hash("oauth_login"),
            email=session["pending_email"],
            first_name=request.form['first_name'],
            last_name=request.form['last_name'],
            address="Not Provided"
        )
        db.session.add(new_user)
        db.session.commit()

        session['username'] = new_user.username
        session.pop("pending_email", None)
        session.pop("pending_username", None)

        subprocess.run(["python", "threat.py"])
        update_ioc()
        return redirect(url_for("dashboard"))

    return render_template("complete.html")


def send_email(recipient, filepath):
    with app.app_context():
        msg = Message('File Upload Notification', sender=app.config['MAIL_USERNAME'], recipients=[recipient])
        msg.body = 'A file has been uploaded. See the attachment.'
        with open(filepath, 'rb') as f:
            msg.attach(os.path.basename(filepath), 'application/octet-stream', f.read())
        mail.send(msg)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'static', 'google.login', 'google.authorized', 'complete_profile']

    if request.endpoint and (
        request.endpoint.startswith('google.') or
        request.endpoint in allowed_routes
    ):
        return

    if 'username' not in session:
        return redirect(url_for('login'))


if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=8080, debug=True)

from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from azure.communication.email import EmailClient
import logging
import random
import string
import pyotp  # Import pyotp library

# Load environment variables
load_dotenv()

# Configure logging
# logging.basicConfig(level=print)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")

# Initialize PyMongo
try:
    mongo = PyMongo(app)
    print("MongoDB connection established successfully.")
except Exception as e:
    logging.error(f"Failed to connect to MongoDB: {e}")

AZURE_CONFIG = {
    "communication_connection_string": os.getenv("AZURE_COMMUNICATION_CONNECTION_STRING")
}

if not AZURE_CONFIG["communication_connection_string"]:
    logging.error("Error: Azure Communication Services connection string not found.")

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def compare_otp(stored_otp, user_otp):
    return stored_otp == user_otp

def email_sender(email, otp):
    try:
        connection_string = AZURE_CONFIG["communication_connection_string"]
        client = EmailClient.from_connection_string(connection_string)

        message = {
            "senderAddress": "DoNotReply@9027cee9-7e9c-432a-b0da-188cb8e3e4ed.azurecomm.net",
            "recipients": {
                "to": [{"address": email}]
            },
            "content": {
                "subject": "OTP Verification",
                "plainText": f"Your OTP for verification is: {otp}",
                "html": f"""
                <html>
                    <body>
                        <h1>OTP Verification</h1>
                        <p>Your OTP for verification is: <strong>{otp}</strong></p>
                    </body>
                </html>"""
            },
        }

        poller = client.begin_send(message)
        result = poller.result()
        return result.message_id is not None

    except Exception as ex:
        logging.error(f"Failed to send OTP email: {ex}")
        return False

def generate_totp_secret():
    return pyotp.random_base32()

def validate_totp(totp_secret, user_totp):  # renamed helper function
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(user_totp)

def is_usual_time():
    now = datetime.now(timezone.utc).astimezone()
    start_time = now.replace(hour=8, minute=0, second=0, microsecond=0)
    end_time = now.replace(hour=20, minute=0, second=0, microsecond=0)
    return start_time <= now <= end_time

def is_known_device(user, user_ip):
    return user_ip in user.get('ips', [])

def determine_auth_method(user, user_ip):
    if is_usual_time():
        if is_known_device(user, user_ip):
            print("User is logging in from a known device during usual time. Password only.")
            return "password"
        else:
            print("User is logging in from an unknown device during usual time. Password+EmailOTP.")
            return "password+EmailOTP"
    else:
        if is_known_device(user, user_ip):
            print("User is logging in from a known device outside usual time. Password+TOTP.")
            return "password+TOTP"
        else:
            print("User is logging in from an unknown device outside usual time. Password+EmailOTP+security.")
            return "password+EmailOTP+security"

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')
        user_ip = request.remote_addr  # Get the user's IP address
        
        if not all([username, email, password, security_question, security_answer]):
            return render_template('register.html', error="All fields are required")

        hashed_password = generate_password_hash(password)
        totp_secret = generate_totp_secret()  # Generate TOTP secret

        try:
            existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
            if existing_user:
                return render_template('register.html', error="Username or email already exists")

            mongo.db.users.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'security_question': security_question,
                'security_answer': security_answer,
                'totp_secret': totp_secret,  # Store TOTP secret
                'ips': [user_ip]    # store registration IP in a single list field
            })
            print(f"User {username} registered successfully from IP {user_ip}.")
            return render_template('register.html', totp_secret=totp_secret)  # Display TOTP secret to the user
        except Exception as e:
            logging.error(f"Failed to register user {username} from IP {user_ip}: {e}")
            return render_template('register.html', error="Registration failed. Please try again.")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_ip = request.remote_addr  # Get the user's IP address

        if not username or not password:
            return render_template('login.html', error="Username and password are required")

        try:
            user = mongo.db.users.find_one({'username': username})
            if user and check_password_hash(user['password'], password):
                auth_method = determine_auth_method(user, user_ip)
                if auth_method == "password":
                    session['username'] = username
                    return redirect(url_for('success'))
                elif auth_method == "password+TOTP":
                    return redirect(url_for('verify_totp', username=username))
                elif auth_method == "password+EmailOTP":
                    otp = generate_otp()
                    mongo.db.otp_tokens.insert_one({
                        'username': username,
                        'otp': otp,
                        'created_at': int(datetime.now(timezone.utc).timestamp())
                    })
                    email_sender(user['email'], otp)
                    return redirect(url_for('verify_otp', username=username))
                else:  # password+EmailOTP+security
                    otp = generate_otp()
                    mongo.db.otp_tokens.insert_one({
                        'username': username,
                        'otp': otp,
                        'created_at': int(datetime.now(timezone.utc).timestamp())
                    })
                    email_sender(user['email'], otp)
                    return redirect(url_for('verify_otp', username=username, extra='security'))
            else:
                logging.warning(f"Failed login attempt for user {username} from IP {user_ip}.")
                return render_template('login.html', error="Invalid username or password")
        except Exception as e:
            logging.error(f"Failed to login user {username} from IP {user_ip}: {e}")
            return render_template('login.html', error="An error occurred. Please try again.")

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'GET':
        username = request.args.get('username')
        extra = request.args.get('extra', '')
        session['verify_otp_extra'] = extra
        logging.debug(f"GET verify_otp: extra={extra}")
        return render_template('verify_otp.html', username=username, extra=extra)

    username = request.form.get('username', '').strip()
    user_otp = request.form.get('otp', '').strip()
    extra = request.form.get('extra') or session.get('verify_otp_extra', '')
    logging.debug(f"POST verify_otp: extra={extra}")
    user_ip = request.remote_addr

    if not username or not user_otp:
        return render_template('verify_otp.html', error="Username and OTP are required", username=username, extra=extra)

    try:
        otp_data = mongo.db.otp_tokens.find_one({'username': username})
        if otp_data:
            stored_otp = otp_data.get('otp', '').strip()
            created_at_timestamp = otp_data.get('created_at')
            created_at = datetime.fromtimestamp(created_at_timestamp, timezone.utc)
            now = datetime.now(timezone.utc)
            otp_age = now - created_at

            if otp_age > timedelta(minutes=5):
                mongo.db.otp_tokens.delete_one({'username': username})
                return render_template('verify_otp.html', error="OTP has expired. Please request a new one.", username=username, extra=extra)

            logging.debug(f"Verifying OTP from IP {user_ip}. Stored: {stored_otp}, Provided: {user_otp}")

            if compare_otp(stored_otp, user_otp):
                mongo.db.otp_tokens.delete_one({'username': username})
                # Pop from session only after successful verification
                session.pop('verify_otp_extra', None)
                if extra == 'security':
                    return redirect(url_for('verify_security_question', username=username))
                else:
                    session['username'] = username
                    return redirect(url_for('success'))
            else:
                return render_template('verify_otp.html', error="Invalid OTP", username=username, extra=extra)
        else:
            return render_template('login.html', error="No OTP found. Please request a new one.", username=username)
    except Exception as e:
        logging.error(f"Failed to verify OTP for {username} from IP {user_ip}: {e}")
        return render_template('verify_otp.html', error="An error occurred. Please try again.", username=username, extra=extra)

@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    if request.method == 'GET':
        username = request.args.get('username')
        return render_template('verify_totp.html', username=username)
    
    username = request.form.get('username', '').strip()
    user_totp = request.form.get('totp', '').strip()  # Get TOTP from the form
    user_ip = request.remote_addr  # Get the user's IP address
    if not username or not user_totp:
        return render_template('verify_totp.html', error="Username and TOTP are required", username=username)

    try:
        user = mongo.db.users.find_one({'username': username})
        if user and validate_totp(user['totp_secret'], user_totp):  # updated function call
            session['username'] = username
            return redirect(url_for('success'))
        else:
            return render_template('verify_totp.html', error="Invalid TOTP", username=username)
    except Exception as e:
        logging.error(f"Failed to verify TOTP for {username} from IP {user_ip}: {e}")
        return render_template('verify_totp.html', error="An error occurred. Please try again.", username=username)

@app.route('/verify_security_question', methods=['GET', 'POST'])
def verify_security_question():
    if request.method == 'GET':
        username = request.args.get('username')
        user = mongo.db.users.find_one({'username': username})
        return render_template('verify_security_question.html', username=username, question=user['security_question'] if user else None)
    
    username = request.form.get('username', '').strip()
    security_answer = request.form.get('security_answer', '').strip()
    user_ip = request.remote_addr  # Get the user's IP address
    if not username or not security_answer:
        return render_template('verify_security_question.html', error="Username and security answer are required", username=username)

    try:
        user = mongo.db.users.find_one({'username': username})
        if user and user['security_answer'] == security_answer:
            session['username'] = username
            return redirect(url_for('success'))
        else:
            return render_template('verify_security_question.html', error="Invalid security answer", username=username)
    except Exception as e:
        logging.error(f"Failed to verify security question for {username} from IP {user_ip}: {e}")
        return render_template('verify_security_question.html', error="An error occurred. Please try again.", username=username)

@app.route('/success')
def success():
    if 'username' in session:
        return render_template('success.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    print("User logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)

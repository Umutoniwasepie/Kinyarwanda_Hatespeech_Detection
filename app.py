from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message, Mail
from datetime import datetime, timedelta
import joblib, re, random, string, time, secrets, requests
import numpy as np
from sqlalchemy import func
import logging
from dotenv import load_dotenv
import os
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_session import Session
import urllib.parse
import json

load_dotenv()

#Setup logging
logging.basicConfig(level=logging.DEBUG)

#Create Flask app
app = Flask(__name__)

#Secret key setup
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logging.warning("No SECRET_KEY found in environment. Using generated key.")
    logging.warning(f"For production, set SECRET_KEY={SECRET_KEY}")

app.secret_key = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

#Session configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('RENDER') is not None  # True in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

#Enable CORS for the extension with proper session support
CORS(app, 
     supports_credentials=True,
     resources={
         r"/api/*": {
             "origins": [
                 "chrome-extension://*",
                 "moz-extension://*", 
                 "http://localhost:*",
                 "http://127.0.0.1:*",
                 "https://kinyarwanda-hatespeech-detection.onrender.com"
             ],
             "methods": ["GET", "POST", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
             "expose_headers": ["Set-Cookie"],
             "supports_credentials": True
         }
     })

#Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

#Check Google OAuth credentials
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')

#Define GOOGLE_AUTH_ENABLED before using it anywhere
GOOGLE_AUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

if not GOOGLE_AUTH_ENABLED:
    logging.warning("Google OAuth credentials not found. Google authentication will be disabled.")
else:
    logging.info("Google OAuth credentials loaded successfully.")

#Base URL function
def get_base_url():
    """Get base URL based on environment"""
    if os.getenv('RENDER'):
        return f"https://{os.getenv('RENDER_EXTERNAL_HOSTNAME')}"
    return os.getenv('BASE_URL', 'http://127.0.0.1:5000') #for local development

BASE_URL = get_base_url()
logging.info(f"Using base URL: {BASE_URL}")

#Google OAuth Configuration
GOOGLE_OAUTH_SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')

#Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kinyaai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#Login setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

def validate_password(password):
    """
    Validate password strength
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    #Check for common passwords
    common_passwords = ['password', '123456', 'password123', 'admin', 'qwerty', 'letmein']
    if password.lower() in common_passwords:
        return False, "Password is too common. Please choose a stronger password"
    
    return True, ""

#Stopwords
kinyarwanda_stopwords = set([
    "na", "ku", "mu", "ya", "y'", "n'", "bya", "cyane", "rwose",
    "kandi", "ubwo", "uko", "ntacyo", "ntukwiye"
])

#Combine both sets
combined_stopwords = kinyarwanda_stopwords.union(ENGLISH_STOP_WORDS)
extra_stopwords = {"lol", "lmao", "smh", "bruh", "nah", "omg", "uhh", "hmm", "yo", "yup"}
combined_stopwords = combined_stopwords.union(extra_stopwords)

#Load models
model = joblib.load('model/lr_model.pkl')
vectorizer = joblib.load('model/tfidf.pkl')
label_encoder = joblib.load('model/label_encoder.pkl')

#Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)  # Allow null for Google OAuth users
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(10), nullable=True)
    role = db.Column(db.String(20), default="user")
    oauth_provider = db.Column(db.String(50), nullable=True)  # Track OAuth provider
    google_id = db.Column(db.String(100), nullable=True)  # Store Google user ID

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    successful = db.Column(db.Boolean, default=False)

class AnalysisHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Allow anonymous access
    tweet_text = db.Column(db.Text, nullable=False)
    predicted_label = db.Column(db.String(50))
    explanation_words = db.Column(db.String(300))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default="web")  # Track source: web, extension, api

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


kinyarwanda_stopwords = set([
    "na", "ku", "mu", "ya", "y'", "n'", "bya", "cyane", "rwose",
    "kandi", "ubwo", "uko", "ntacyo", "ntukwiye"
])

#Combine both sets
combined_stopwords = kinyarwanda_stopwords.union(ENGLISH_STOP_WORDS)
extra_stopwords = {"lol", "lmao", "smh", "bruh", "nah", "omg", "uhh", "hmm", "yo", "yup"}
combined_stopwords = combined_stopwords.union(extra_stopwords)

def preprocess_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'@\w+|http\S+|\d+', '', text)
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    
    words = text.split()
    words = [word for word in words if word not in combined_stopwords]
    
    return ' '.join(words)

def get_explanation_words_lr(text, model, vectorizer, predicted_class, top_n=5):
    """Get explanation using logistic regression coefficients"""
    try:
        #Get feature names and coefficients
        feature_names = vectorizer.get_feature_names_out()
        coefficients = model.coef_[predicted_class]  #Get coefficients for predicted class
        
        # Transform the input text
        cleaned = preprocess_text(text)
        vec = vectorizer.transform([cleaned])
        feature_indices = vec.nonzero()[1]
        
        word_importance = []
        for idx in feature_indices:
            word = feature_names[idx]
            coef = coefficients[idx]
            tfidf_val = vec[0, idx]
            importance = abs(coef * tfidf_val)  #Use absolute value
            word_importance.append((word, importance))
        
        #Sort by importance and return top words
        word_importance.sort(key=lambda x: x[1], reverse=True)
        explanation_words = [word for word, _ in word_importance[:top_n]]
        
        return explanation_words
        
    except Exception as e:
        print(f"LR explanation failed: {e}")
        #Fallback to simple word extraction
        cleaned = preprocess_text(text)
        words = cleaned.split()
        feature_names = vectorizer.get_feature_names_out()
        vocab_words = [word for word in words if word in feature_names]
        return list(dict.fromkeys(vocab_words))[:top_n]
        
def generate_code(length=7):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
def send_email_with_sendgrid(to_email, subject, html_content, text_content):
    """Send email using SendGrid REST API"""
    if not SENDGRID_API_KEY:
        logging.error("SendGrid API key not configured")
        return False
    
    url = "https://api.sendgrid.com/v3/mail/send"
    
    data = {
        "personalizations": [
            {
                "to": [{"email": to_email}],
                "subject": subject
            }
        ],
        "from": {"email": "longelee333@gmail.com", "name": "RHD Team"},
        "content": [
            {"type": "text/plain", "value": text_content},
            {"type": "text/html", "value": html_content}
        ]
    }
    
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        logging.info(f"Email sent successfully to {to_email}")
        return True
    except requests.RequestException as e:
        logging.error(f"Failed to send email via SendGrid API: {e}")
        return False

#send emails
def send_verification_email(email, code):
    subject = "Your RHD verification code"
    text_content = f"""
Hello,

Thanks for signing up with RHD. Please use the verification code below to complete your registration:

Verification Code: {code}

If you didn't request this, you can safely ignore this message.

– The RHD Team
"""
    html_content = f"""
<p>Hello,</p>
<p>Thanks for signing up with <strong>RHD</strong>.</p>
<p>Please use the verification code below to complete your registration:</p>
<h2 style="color:#2e6c80;">{code}</h2>
<p>If you didn't request this, you can safely ignore this message.</p>
<p style="margin-top:20px;">– The RHD Team</p>
"""
    return send_email_with_sendgrid(email, subject, html_content, text_content)

def send_reset_email(email, code):
    subject = "Password Reset - RHD"
    text_content = f"""
Hello,

You requested a password reset for your RHD account.

Reset Code: {code}

If you didn't request this, please ignore this email.

– The RHD Team
"""
    html_content = f"""
<p>Hello,</p>
<p>You requested a password reset for your <strong>RHD</strong> account.</p>
<p>Please use the reset code below:</p>
<h2 style="color:#2e6c80;">{code}</h2>
<p>If you didn't request this, please ignore this email.</p>
<p style="margin-top:20px;">– The RHD Team</p>
"""
    return send_email_with_sendgrid(email, subject, html_content, text_content)
    
# Google OAuth Helper Functions
def get_google_auth_url():
    """Generate Google OAuth authorization URL"""
    if not GOOGLE_AUTH_ENABLED:
        return None
    
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': f"{BASE_URL}/auth/google/callback",
        'scope': ' '.join(GOOGLE_OAUTH_SCOPES),
        'response_type': 'code',
        'access_type': 'offline',
        'state': secrets.token_urlsafe(32)  #CSRF protection
    }
    
    #Store state in session for verification
    session['oauth_state'] = params['state']
    
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params)
    return auth_url

def exchange_code_for_token(code, state):
    """Exchange authorization code for access token"""
    if not GOOGLE_AUTH_ENABLED:
        return None
    
    #Verify state parameter (CSRF protection)
    if state != session.get('oauth_state'):
        logging.error("OAuth state mismatch")
        return None
    
    #Clear the state from session
    session.pop('oauth_state', None)
    
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'code': code,
        'redirect_uri': f"{BASE_URL}/auth/google/callback",
        'grant_type': 'authorization_code'
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error exchanging code for token: {e}")
        return None

def get_google_user_info(access_token):
    """Get user info from Google using access token"""
    user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.get(user_info_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error fetching user info: {e}")
        return None

#Rate limiting
user_last_requests = {}

@app.before_request
def rate_limit():
    #skip rate limiting for extension API calls
    if request.endpoint == 'api_analyze_public':
        return
        
    if current_user.is_authenticated:
        uid = current_user.id
        now = time.time()
        window = 60
        max_requests = 10
        timestamps = user_last_requests.get(uid, [])
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= max_requests:
            abort(429, description="Rate limit exceeded. Try again shortly.")
        timestamps.append(now)
        user_last_requests[uid] = timestamps

def get_moderator_stats():
    total_users = User.query.count()
    total_flagged = AnalysisHistory.query.filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"])
    ).count()

    counts_by_label = db.session.query(
        AnalysisHistory.predicted_label, func.count(AnalysisHistory.id)
    ).filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"])
    ).group_by(AnalysisHistory.predicted_label).all()
    counts_dict = {label: count for label, count in counts_by_label}

    # Updated to include usernames
    top_users = db.session.query(
        User.username,
        func.count(AnalysisHistory.id).label("flagged_count")
    ).join(
        AnalysisHistory, User.id == AnalysisHistory.user_id
    ).filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"])
    ).group_by(User.username).order_by(func.count(AnalysisHistory.id).desc()).limit(5).all()

    explanations = AnalysisHistory.query.with_entities(AnalysisHistory.explanation_words).filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"])
    ).all()
    word_freq = {}
    for (expl,) in explanations:
        if expl:
            words = expl.split(", ")
            for w in words:
                word_freq[w] = word_freq.get(w, 0) + 1
    top_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]

    week_ago = datetime.utcnow() - timedelta(days=7)
    flagged_week = AnalysisHistory.query.filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"]),
        AnalysisHistory.timestamp >= week_ago
    ).count()

    avg_flagged_per_user = total_flagged / total_users if total_users else 0

    total_analyses = AnalysisHistory.query.count()
    flagged_percentage = (total_flagged / total_analyses * 100) if total_analyses else 0

    return {
        "total_users": total_users,
        "total_flagged": total_flagged,
        "counts_by_label": counts_dict,
        "top_users": top_users,
        "top_words": top_words,
        "flagged_week": flagged_week,
        "avg_flagged_per_user": avg_flagged_per_user,
        "flagged_percentage": flagged_percentage,
    }

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'user' else 'moderator_dashboard'))
    return render_template('index.html', google_auth_enabled=GOOGLE_AUTH_ENABLED)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'user')

        # Validate password confirmation
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        # Validate password strength
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, "danger")
            return redirect(url_for("register"))
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))

        code = generate_code()
        hashed_pw = generate_password_hash(password)
        user = User(
            full_name=full_name,
            username=username,
            email=email,
            password_hash=hashed_pw,
            verification_code=code,
            role=role
        )
        db.session.add(user)
        db.session.commit()

        sent = send_verification_email(email, code)
        if not sent:
            flash("Failed to send verification email. Please contact support.", "danger")
            logging.error("Email sending failed on registration.")
        else:
            flash("Verification code sent. Please check your email.", "info")

        return redirect(url_for("verify", username=username))
    return render_template("register.html", google_auth_enabled=GOOGLE_AUTH_ENABLED)


@app.route('/verify/<username>', methods=['GET', 'POST'])
def verify(username):
    user = User.query.filter_by(username=username).first_or_404()

    # Cooldown timer stored in session for resend button
    resend_cooldown = session.get('resend_cooldown', 0)
    can_resend = time.time() > resend_cooldown

    if request.method == 'POST':
        if 'code' in request.form:
            entered_code = request.form['code'].strip().upper()  # Add this line
            stored_code = user.verification_code.strip().upper() if user.verification_code else ""  # Add this line
            
            if entered_code == stored_code:
                user.is_verified = True
                user.verification_code = None
                db.session.commit()
            
                login_user(user)    
                flash("Account verified successfully! Welcome to RHD.", "success")
                
                if user.role == "moderator": #Redirect to appropriate dashboard based on role
                    return redirect(url_for("moderator_dashboard"))
                else:
                    return redirect(url_for("dashboard"))
            else:
                flash("Incorrect verification code. Please try again.", "danger")
        elif 'resend' in request.form and can_resend:
            new_code = generate_code()
            user.verification_code = new_code
            db.session.commit()
            sent = send_verification_email(user.email, new_code)
            if sent:
                flash("Verification code resent. Please check your email.", "info")
                session['resend_cooldown'] = time.time() + 60  #60 seconds cooldown
            else:
                flash("Failed to resend code. Please try again later.", "danger")
        elif 'resend' in request.form and not can_resend:
            wait_time = int(resend_cooldown - time.time())
            flash(f"Please wait {wait_time} seconds before resending code.", "warning")

    return render_template("verify.html", username=username, can_resend=can_resend)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user and user.password_hash:  #only for non-OAuth users
            reset_code = generate_code()
            user.verification_code = reset_code  #reuse verification_code field
            db.session.commit()
            
            sent = send_reset_email(email, reset_code)
            if sent:
                flash("Password reset code sent to your email.", "info")
                return redirect(url_for("reset_password", email=email))
            else:
                flash("Failed to send reset email. Please try again.", "danger")
        else:
            #don't reveal if email exists for security
            flash("If that email exists, you'll receive a reset code.", "info")
    
    return render_template("forgot_password.html")

@app.route('/reset-password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("login"))
    
    if request.method == 'POST':
        entered_code = request.form['code'].strip().upper()
        stored_code = user.verification_code.strip().upper() if user.verification_code else ""
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if entered_code != stored_code:
            flash("Invalid reset code.", "danger")
            return render_template("reset_password.html", email=email)
        
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", email=email)
        
        #Validate new password
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            flash(error_msg, "danger")
            return render_template("reset_password.html", email=email)
        
        #Update password
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        user.verification_code = None
        db.session.commit()
        
        flash("Password reset successfully! Please log in.", "success")
        return redirect(url_for("login"))
    
    return render_template("reset_password.html", email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        #Check for too many failed attempts
        failed_attempts = LoginAttempt.query.filter_by(
            ip_address=ip_address,
            successful=False
        ).filter(
            LoginAttempt.timestamp >= datetime.utcnow() - timedelta(minutes=15)
        ).count()
        
        if failed_attempts >= 5:
            flash("Too many failed login attempts. Please try again in 15 minutes.", "danger")
            return render_template("login.html", google_auth_enabled=GOOGLE_AUTH_ENABLED)
        
        user = User.query.filter_by(username=username).first()
        
        #Log the attempt
        attempt = LoginAttempt(
            ip_address=ip_address,
            username=username,
            successful=False
        )
        
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash("Please verify your email first.", "warning")
                return redirect(url_for("verify", username=user.username))
            
            #Mark attempt as successful
            attempt.successful = True
            db.session.add(attempt)
            db.session.commit()
            
            login_user(user)
            flash("Logged in successfully!", "success")
            
            # Redirect based on role
            if user.role == "moderator":
                return redirect(url_for("moderator_dashboard"))
            else:
                return redirect(url_for("dashboard"))
        else:
            db.session.add(attempt)
            db.session.commit()
            flash("Invalid username or password. Please try again.", "danger")
    
    return render_template("login.html", google_auth_enabled=GOOGLE_AUTH_ENABLED)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    
    #Clear any existing flash messages
    session.pop('_flashes', None)
    
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


#Google OAuth Routes
@app.route('/auth/google')
def auth_google():
    """Initiate Google OAuth"""
    if not GOOGLE_AUTH_ENABLED:
        flash("Google authentication is not configured.", "danger")
        return redirect(url_for('login'))
    
    auth_url = get_google_auth_url()
    if not auth_url:
        flash("Failed to generate Google auth URL.", "danger")
        return redirect(url_for('login'))
    
    return redirect(auth_url)

@app.route('/auth/google/callback')
def auth_google_callback():
    """Handle Google OAuth callback"""
    if not GOOGLE_AUTH_ENABLED:
        flash("Google authentication is not configured.", "danger")
        return redirect(url_for('login'))
    
    #Get authorization code and state from query parameters
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        flash(f"Google authentication failed: {error}", "danger")
        return redirect(url_for('login'))
    
    if not code:
        flash("No authorization code received from Google.", "danger")
        return redirect(url_for('login'))
    
    #Exchange code for token
    token_data = exchange_code_for_token(code, state)
    if not token_data:
        flash("Failed to get access token from Google.", "danger")
        return redirect(url_for('login'))
    
    access_token = token_data.get('access_token')
    if not access_token:
        flash("No access token received from Google.", "danger")
        return redirect(url_for('login'))
    
    #Get user info
    user_info = get_google_user_info(access_token)
    if not user_info:
        flash("Failed to get user information from Google.", "danger")
        return redirect(url_for('login'))
    
    email = user_info.get('email')
    google_id = user_info.get('id')
    name = user_info.get('name', '')
    
    if not email or not google_id:
        flash("Incomplete user information from Google.", "danger")
        return redirect(url_for('login'))
    
    #Get role from session (set during registration flow)
    pending_role = session.pop('pending_role', 'user')
    
    #Check if user exists
    user = User.query.filter_by(email=email).first()
    
    if not user:
        #Create new user with the selected role
        username_base = email.split("@")[0]
        username = username_base
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{username_base}_{counter}"
            counter += 1
        
        user = User(
            full_name=name or username,
            username=username,
            email=email,
            is_verified=True,  # Google accounts are pre-verified
            oauth_provider="google",
            google_id=google_id,
            role=pending_role  # Use the role from session
        )
        db.session.add(user)
        db.session.commit()
        flash(f"Account created successfully with Google as {pending_role}!", "success")
    else:
        if not user.google_id:
            user.google_id = google_id
            user.oauth_provider = "google"
            user.is_verified = True
            db.session.commit()
        else:
            if user.role != pending_role:
                flash(f"You already signed up as a '{user.role}'. Contact support to change your role.", "warning")
    login_user(user, remember=True)
    
    flash("Logged in with Google!", "success")
    return redirect(url_for("dashboard" if user.role == "user" else "moderator_dashboard"))

@app.route('/auth/google/register', methods=['POST'])
def auth_google_register():
    """Store role selection in session before Google OAuth"""
    if not GOOGLE_AUTH_ENABLED:
        flash("Google authentication is not configured.", "danger")
        return redirect(url_for('register'))
    
    # Store the selected role in session
    role = request.form.get('role', 'user')
    session['pending_role'] = role
    
    # Redirect to Google OAuth
    auth_url = get_google_auth_url()
    if not auth_url:
        flash("Failed to generate Google auth URL.", "danger")
        return redirect(url_for('register'))
    
    return redirect(auth_url)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role != "user":
        return redirect(url_for('moderator_dashboard'))

    result, explanation_words, raw_text = None, [], ""

    if request.method == 'POST':
        raw_text = request.form.get('tweet', '').strip()
        if not raw_text:
            flash("Please enter text to analyze.", "warning")
            return redirect(url_for('dashboard'))

        cleaned = preprocess_text(raw_text)
        print(f"DEBUG - Raw text: {raw_text}")
        print(f"DEBUG - Cleaned text: {cleaned}")
            
        vec = vectorizer.transform([cleaned])
        print(f"DEBUG - Vector shape: {vec.shape}")

        proba = model.predict_proba(vec)[0]
        pred = np.argmax(proba)
            
        print(f"DEBUG - Prediction probabilities: {proba}")
        print(f"DEBUG - Max probability: {max(proba)} at index: {pred}")
        print(f"DEBUG - Model prediction (numeric): {pred}")
        print(f"DEBUG - Label encoder classes: {label_encoder.classes_}")
            
        label = label_encoder.inverse_transform([pred])[0]
        print(f"DEBUG - Final label: {label}")
        
        explanation_words = get_explanation_words_lr(raw_text, model, vectorizer, pred)

        db.session.add(AnalysisHistory(
            user_id=current_user.id,
            tweet_text=raw_text,
            predicted_label=label,
            explanation_words=", ".join(explanation_words),
            source="web"
        ))
        db.session.commit()
        result = label

    history = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(AnalysisHistory.timestamp.desc()).all()
    return render_template("dashboard.html", result=result, text=raw_text, explanation=explanation_words, history=history)

@app.route('/moderator')
@login_required
def moderator_dashboard():
    if current_user.role != "moderator":
        abort(403)
    flagged = db.session.query(AnalysisHistory, User.username).outerjoin(
        User, AnalysisHistory.user_id == User.id
    ).filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"])
    ).order_by(AnalysisHistory.timestamp.desc()).all()

    stats = get_moderator_stats()

    return render_template("moderator_dashboard.html", flagged=flagged, stats=stats)

@app.route('/moderator/export')
@login_required
def export_flagged():
    if current_user.role != "moderator":
        abort(403)
    
    # Join with User table to get usernames
    flagged = db.session.query(AnalysisHistory, User.username).outerjoin(
        User, AnalysisHistory.user_id == User.id
    ).filter(
        AnalysisHistory.predicted_label.in_(["offensive", "hate"])
    ).order_by(AnalysisHistory.timestamp.desc()).all()

    output = []
    output.append(['User', 'Tweet', 'Label', 'Explanation', 'Timestamp'])
    for item, username in flagged:
        output.append([
            username if username else 'Anonymous',
            item.tweet_text,
            item.predicted_label,
            item.explanation_words or "",
            item.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        ])

    response = make_response('\n'.join([','.join(map(str, row)) for row in output]))
    response.headers['Content-Disposition'] = 'attachment; filename=flagged_reports.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    if not request.json or 'text' not in request.json:
        return jsonify({'error': 'Missing text'}), 400

    raw_text = request.json['text']
    cleaned = preprocess_text(raw_text)
    print(f"DEBUG - Raw text: {raw_text}")
    print(f"DEBUG - Cleaned text: {cleaned}")
        
    vec = vectorizer.transform([cleaned])
    print(f"DEBUG - Vector shape: {vec.shape}")

    proba = model.predict_proba(vec)[0]
    pred = np.argmax(proba)
        
    print(f"DEBUG - Prediction probabilities: {proba}")
    print(f"DEBUG - Max probability: {max(proba)} at index: {pred}")
    print(f"DEBUG - Model prediction (numeric): {pred}")
    print(f"DEBUG - Label encoder classes: {label_encoder.classes_}")
        
    label = label_encoder.inverse_transform([pred])[0]
    print(f"DEBUG - Final label: {label}")
    explanation_words = get_explanation_words_lr(raw_text, model, vectorizer, pred)

    db.session.add(AnalysisHistory(
        user_id=current_user.id,
        tweet_text=raw_text,
        predicted_label=label,
        explanation_words=", ".join(explanation_words),
        source="api"
    ))
    db.session.commit()

    return jsonify({
        'prediction': label,
        'explanation': explanation_words
    })


@app.route('/api/analyze/public', methods=['POST'])
def api_analyze_public():
    try:
        # Validate request
        if not request.json or 'text' not in request.json:
            return jsonify({'error': 'Missing text parameter'}), 400

        raw_text = request.json['text']
        
        # Basic validation
        if not raw_text or len(raw_text.strip()) == 0:
            return jsonify({'error': 'Empty text provided'}), 400
        
        if len(raw_text) > 1000:  # Limit text length
            return jsonify({'error': 'Text too long (max 1000 characters)'}), 400

        # Process the text
        cleaned = preprocess_text(raw_text)
        print(f"DEBUG - Raw text: {raw_text}")
        print(f"DEBUG - Cleaned text: {cleaned}")
        
        # Check if cleaned text is empty
        if not cleaned:
            return jsonify({
                'prediction': 'normal',
                'explanation': [],
                'status': 'success',
                'message': 'No analyzable content found'
            })
        
        vec = vectorizer.transform([cleaned])
        print(f"DEBUG - Vector shape: {vec.shape}")
        # Get prediction probabilities and use the class with highest probability
        proba = model.predict_proba(vec)[0]
        pred = np.argmax(proba)
        
        print(f"DEBUG - Prediction probabilities: {proba}")
        print(f"DEBUG - Max probability: {max(proba)} at index: {pred}")
        print(f"DEBUG - Model prediction (numeric): {pred}")
        print(f"DEBUG - Label encoder classes: {label_encoder.classes_}")
        
        label = label_encoder.inverse_transform([pred])[0]
        print(f"DEBUG - Final label: {label}")

        explanation_words = get_explanation_words_lr(raw_text, model, vectorizer, pred)

        #log anonymous usage
        try:
            db.session.add(AnalysisHistory(
                user_id=None,
                tweet_text=raw_text,
                predicted_label=label,
                explanation_words=", ".join(explanation_words),
                source="extension"
            ))
            db.session.commit()
        except Exception as db_error:
            print(f"Database logging error: {db_error}")
            # Continue without failing the request

        response_data = {
            'prediction': label,
            'explanation': explanation_words,
            'status': 'success',
            'debug': {
                'numeric_prediction': int(pred),
                'probabilities': proba.tolist(),
                'cleaned_text': cleaned,
                'confidence': float(max(proba))
            }
        }
        
        return jsonify(response_data)

    except Exception as e:
        logging.error(f"Error in public API: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'error': f'Analysis failed: {str(e)}',
            'status': 'error'
        }), 500

@app.route("/clear-session")
def clear_session():
    session.clear()
    return "Session cleared!"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        logging.info("Database tables created successfully")
    app.run(debug=True)
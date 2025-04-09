import os
import logging
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_socketio import SocketIO
from flask_mail import Mail
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database setup
class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
socketio = SocketIO()
mail = Mail()

# Create app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# App configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///chat.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Email configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.environ.get("EMAIL_PASS")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("EMAIL_USER")

# Log email configuration status
logger.info(f"Email configuration - Username: {app.config['MAIL_USERNAME'] != None}, Password: {app.config['MAIL_PASSWORD'] != None}")

# Initialize extensions with app
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
socketio.init_app(app, cors_allowed_origins="*")
mail.init_app(app)

# Create serializer for tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Import models and routes after app creation to avoid circular imports
with app.app_context():
    from models import User, Room, Message
    import routes
    
    # Create database tables
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        from werkzeug.security import generate_password_hash
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin'),
            is_admin=True,
            is_verified=True
        )
        db.session.add(admin)
        
        # Create general room
        general_room = Room(name='General', created_by=1)
        db.session.add(general_room)
        
        # Create welcome message
        welcome_msg = Message(
            content='Welcome to Blazer Chat!',
            timestamp=datetime.utcnow(),
            user_id=1,
            room_id=1
        )
        db.session.add(welcome_msg)
        
        db.session.commit()
        logger.info("Created admin user and general room")

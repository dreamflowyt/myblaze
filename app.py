from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail
from flask_mail import Message as MailMessage
from datetime import datetime
import os
import logging
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Basic Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Production Security Settings
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
app.config['REMEMBER_COOKIE_SECURE'] = os.environ.get('REMEMBER_COOKIE_SECURE', 'True').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')

# Check if email credentials are configured
EMAIL_CONFIGURED = bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])
if not EMAIL_CONFIGURED:
    logger.warning("Email configuration is not complete. Please check your .env file.")

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='threading',
                   ping_timeout=60,
                   ping_interval=25,
                   max_http_buffer_size=1e8,
                   logger=True,
                   engineio_logger=True,
                   allow_upgrades=True,
                   transports=['websocket', 'polling'],
                   cookie=False,
                   manage_session=False,
                   max_retries=5,
                   retry_delay=1000)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Create a serializer for email verification tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize Flask-Mail
mail.init_app(app)

# Define the online_users list
online_users = []

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='author', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    messages = db.relationship('Message', backref='room', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)

# Create database tables and admin user if it doesn't exist
with app.app_context():
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(username='joji').first()
    if not admin:
        admin = User(
            username='joji',
            email='joji@example.com',
            password='joji0107',
            is_admin=True,
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        logger.info("Admin user 'joji' created successfully")
    
    # Create general room if it doesn't exist
    general_room = Room.query.filter_by(name='general').first()
    if not general_room:
        general_room = Room(name='general')
        db.session.add(general_room)
        db.session.commit()
        logger.info("Created general room")

# Routes
@app.route('/')
def index():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('chat'))
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:  # In production, use proper password hashing
            if not user.is_verified:
                flash('Please verify your email address before logging in.', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('chat'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"Form data received - Username: {username}, Email: {email}, Password: {password}")
        print(f"All form data: {request.form}")
        
        if not email:
            flash('Email is required')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
            
        user = User(username=username, email=email, password=password)  # In production, hash the password
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        send_verification_email(user)
        
        if EMAIL_CONFIGURED:
            flash('Registration successful! Please check your email to verify your account.', 'success')
        else:
            flash('Registration successful! You can now log in.', 'success')
            
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/chat')
@login_required
def chat():
    rooms = Room.query.all()
    return render_template('chat.html', rooms=rooms)

@app.route('/create_room', methods=['POST'])
@login_required
def create_room():
    room_name = request.form.get('room_name')
    if Room.query.filter_by(name=room_name).first():
        flash('Room already exists')
        return redirect(url_for('chat'))
    
    room = Room(name=room_name)
    db.session.add(room)
    db.session.commit()
    return redirect(url_for('chat'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Socket.IO events
@socketio.on('connect')
def handle_connect(auth):
    print(f"Client connected: {request.sid}")
    # Add user to online users list
    if current_user.is_authenticated:
        online_users.append(current_user.username)
        emit('user_list', {'users': [{'username': user, 'online': True} for user in online_users]}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Remove user from online users list
    if current_user.is_authenticated:
        if current_user.username in online_users:
            online_users.remove(current_user.username)
        emit('user_list', {'users': [{'username': user, 'online': True} for user in online_users]}, broadcast=True)

@socketio.on('join')
def handle_join(data):
    try:
        room = data.get('room', 'general')
        room_obj = Room.query.filter_by(name=room).first()
        if not room_obj:
            room_obj = Room(name=room)
            db.session.add(room_obj)
            db.session.commit()
        
        join_room(room)
        if current_user.is_authenticated:
            logger.info(f"User {current_user.username} joined room: {room}")
            emit('status', {'msg': f"{current_user.username} has joined the room."}, room=room)
            # Retrieve and send previous messages in the room
            messages = Message.query.filter_by(room_id=room_obj.id).order_by(Message.timestamp).all()
            for message in messages:
                emit('message', {
                    'username': message.author.username,
                    'message': message.content,
                    'timestamp': message.timestamp.strftime('%H:%M:%S')
                }, room=room)
    except Exception as e:
        logger.error(f"Error in handle_join: {str(e)}")
        emit('error', {'message': 'Error joining room'})

@socketio.on('leave')
def handle_leave(data):
    room = data.get('room')
    if room:
        leave_room(room)
        print(f"User {current_user.username} left room: {room}")
        emit('status', {'msg': f"{current_user.username} has left the room."}, room=room)

@socketio.on('message')
def handle_message(data):
    try:
        room = data.get('room', 'general')
        message_content = data.get('message', '')
        username = data.get('username', current_user.username)
        
        if message_content and room:
            logger.info(f"Message in {room} from {username}: {message_content}")
            # Store the message in the database
            room_obj = Room.query.filter_by(name=room).first()
            if not room_obj:
                room_obj = Room(name=room)
                db.session.add(room_obj)
                db.session.commit()
            
            message = Message(content=message_content, author=current_user, room=room_obj)
            db.session.add(message)
            db.session.commit()
            # Emit the message to the room
            emit('message', {
                'username': username,
                'message': message_content,
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }, room=room)
    except Exception as e:
        logger.error(f"Error in handle_message: {str(e)}")
        emit('error', {'message': 'Error sending message'})

@socketio.on('get_rooms')
def handle_get_rooms():
    try:
        rooms = [{'name': room.name} for room in Room.query.all()]
        emit('room_list', {'rooms': rooms})
    except Exception as e:
        logger.error(f"Error in handle_get_rooms: {str(e)}")
        emit('room_list', {'rooms': []})

@socketio.on('create_room')
def handle_create_room(data):
    try:
        room_name = data.get('room')
        if room_name:
            # Check if room already exists
            existing_room = Room.query.filter_by(name=room_name).first()
            if not existing_room:
                new_room = Room(name=room_name)
                db.session.add(new_room)
                db.session.commit()
                logger.info(f"Room created: {room_name}")
                emit('room_list', {'rooms': [{'name': room.name} for room in Room.query.all()]}, broadcast=True)
            else:
                logger.info(f"Room already exists: {room_name}")
    except Exception as e:
        logger.error(f"Error in handle_create_room: {str(e)}")
        emit('error', {'message': 'Error creating room'})

@socketio.on('get_users')
def handle_get_users():
    try:
        users = [{'username': user.username, 'online': user.username in online_users} for user in User.query.all()]
        emit('user_list', {'users': users})
    except Exception as e:
        logger.error(f"Error in handle_get_users: {str(e)}")
        emit('user_list', {'users': []})

# Admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.is_admin:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in admin_required decorator: {str(e)}")
            return redirect(url_for('index'))
    return decorated_function

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        users = User.query.all()
        rooms = Room.query.all()
        messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
        return render_template('admin/dashboard.html', users=users, rooms=rooms, messages=messages)
    except Exception as e:
        logger.error(f"Error in admin_dashboard: {str(e)}")
        return redirect(url_for('index'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    try:
        users = User.query.all()
        return render_template('admin/users.html', users=users)
    except Exception as e:
        logger.error(f"Error in admin_users: {str(e)}")
        return redirect(url_for('index'))

@app.route('/admin/rooms')
@login_required
@admin_required
def admin_rooms():
    try:
        rooms = Room.query.all()
        return render_template('admin/rooms.html', rooms=rooms)
    except Exception as e:
        logger.error(f"Error in admin_rooms: {str(e)}")
        return redirect(url_for('index'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash('You cannot delete your own account')
            return redirect(url_for('admin_users'))
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted')
        return redirect(url_for('admin_users'))
    except Exception as e:
        logger.error(f"Error in delete_user: {str(e)}")
        flash('Error deleting user')
        return redirect(url_for('admin_users'))

@app.route('/admin/delete_room/<int:room_id>', methods=['POST'])
@login_required
@admin_required
def delete_room(room_id):
    try:
        room = Room.query.get_or_404(room_id)
        
        # First delete all messages in the room
        Message.query.filter_by(room_id=room_id).delete()
        
        # Then delete the room
        db.session.delete(room)
        db.session.commit()
        
        flash(f'Room {room.name} has been deleted')
        return redirect(url_for('admin_rooms'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in delete_room: {str(e)}")
        flash('Error deleting room')
        return redirect(url_for('admin_rooms'))

@app.route('/admin/delete_message/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def delete_message(message_id):
    try:
        message = Message.query.get_or_404(message_id)
        db.session.delete(message)
        db.session.commit()
        flash('Message has been deleted')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        logger.error(f"Error in delete_message: {str(e)}")
        flash('Error deleting message')
        return redirect(url_for('admin_dashboard'))

@app.route('/remove_normal_users', methods=['GET'])
@login_required
@admin_required
def remove_normal_users():
    try:
        # Delete all users except admins
        User.query.filter_by(is_admin=False).delete()
        db.session.commit()
        flash('All normal users have been removed.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in remove_normal_users: {str(e)}")
        flash(f'Error removing users: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# Email verification functions
def send_verification_email(user):
    if not EMAIL_CONFIGURED:
        print(f"Email verification skipped: Email credentials not configured")
        print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
        print(f"MAIL_PASSWORD: {'Set' if app.config['MAIL_PASSWORD'] else 'Not set'}")
        # Mark user as verified automatically for development
        user.is_verified = True
        db.session.commit()
        return
        
    token = serializer.dumps(user.email, salt='email-verification-salt')
    verification_link = url_for('verify_email', token=token, _external=True)
    
    try:
        print(f"Attempting to send verification email to: {user.email}")
        print(f"Using SMTP server: {app.config['MAIL_SERVER']}")
        print(f"Using port: {app.config['MAIL_PORT']}")
        print(f"Using TLS: {app.config['MAIL_USE_TLS']}")
        
        msg = MailMessage(
            subject='Verify your email address',
            recipients=[user.email],
            html=render_template('email/verification.html', verification_link=verification_link)
        )
        
        mail.send(msg)
        print("Verification email sent successfully")
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        # Mark user as verified automatically in case of email error
        user.is_verified = True
        db.session.commit()

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=3600)  # Token expires in 1 hour
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_verified = True
            db.session.commit()
            flash('Your email has been verified! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification link.', 'danger')
    except:
        flash('The verification link is invalid or has expired.', 'danger')
    return redirect(url_for('index'))

# Add resend verification email route
@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user and not user.is_verified:
            send_verification_email(user)
            flash('Verification email has been resent. Please check your inbox.', 'success')
        elif user and user.is_verified:
            flash('Your email is already verified. You can log in.', 'info')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('login'))
    return render_template('resend_verification.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 
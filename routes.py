from flask import render_template, flash, redirect, url_for, request, jsonify, abort
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db, socketio, serializer
from models import User, Room, Message, UserRoom, MessageReaction
from forms import (RegistrationForm, LoginForm, CreateRoomForm, 
                  MessageForm, ResetPasswordRequestForm, ResetPasswordForm)
from email_utils import send_verification_email
from flask_socketio import join_room, leave_room, emit
from datetime import datetime, timedelta
import uuid
import logging

logger = logging.getLogger(__name__)

# Home route
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('rooms'))
    return render_template('index.html', title='Blazer Chat')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('rooms'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        
        # Check if email already exists
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash('This email is already registered. Please login or use a different email.', 'danger')
            return redirect(url_for('register'))
            
        # Check if username already exists
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            flash('This username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
            
        # Generate verification token
        token = str(uuid.uuid4())
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            verification_token=token,
            is_verified=False
        )
        
        # Try to send the verification email before committing to database
        if send_verification_email(user):
            db.session.add(user)
            db.session.commit()
            logger.info(f"New user registered: {form.username.data} ({form.email.data})")
            flash('Your account has been created! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        else:
            flash('There was a problem sending the verification email. Please try again later.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html', title='Register', form=form)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('rooms'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if not user:
            flash('No account found with this email. Please register first.', 'danger')
            return redirect(url_for('login'))
            
        if not check_password_hash(user.password_hash, form.password.data):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('login'))
            
        if not user.is_verified:
            # Allow resending the verification email
            flash('Your email is not verified. Please check your inbox or click below to resend the verification email.', 'warning')
            return render_template('login.html', title='Login', form=form, 
                                 unverified_user_id=user.id)
                
        # User is verified and password is correct
        login_user(user, remember=form.remember.data)
        next_page = request.args.get('next')
        flash('Login successful!', 'success')
        return redirect(next_page if next_page else url_for('rooms'))
    
    return render_template('login.html', title='Login', form=form)

# Resend verification email
@app.route('/resend_verification/<int:user_id>')
def resend_verification(user_id):
    user = User.query.get_or_404(user_id)
    
    # Generate new token
    token = str(uuid.uuid4())
    user.verification_token = token
    db.session.commit()
    
    # Send verification email
    if send_verification_email(user):
        flash('Verification email has been resent. Please check your inbox.', 'success')
    else:
        flash('Failed to send verification email. Please try again later.', 'danger')
    
    return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Verify email route
@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    
    if user:
        user.is_verified = True
        user.verification_token = None
        
        # Add user to General room
        general_room = Room.query.filter_by(name='General').first()
        if general_room:
            user_room = UserRoom(user_id=user.id, room_id=general_room.id)
            db.session.add(user_room)
        
        db.session.commit()
        flash('Email verification successful! You can now login.', 'success')
        return render_template('verify_success.html')
    else:
        flash('The verification link is invalid or has expired.', 'danger')
        return render_template('verify_failed.html')

# Rooms route
@app.route('/rooms')
@login_required
def rooms():
    create_room_form = CreateRoomForm()
    
    # Get rooms that the user is a member of
    user_rooms = UserRoom.query.filter_by(user_id=current_user.id).all()
    rooms = [user_room.room for user_room in user_rooms]
    
    # Get other available rooms
    other_rooms = Room.query.filter(~Room.id.in_([room.id for room in rooms])).all() if rooms else Room.query.all()
    
    return render_template('rooms.html', title='Chat Rooms', 
                          rooms=rooms, other_rooms=other_rooms,
                          create_room_form=create_room_form)

# Create room route
@app.route('/rooms/create', methods=['POST'])
@login_required
def create_room():
    form = CreateRoomForm()
    
    if form.validate_on_submit():
        room = Room(name=form.name.data, created_by=current_user.id)
        db.session.add(room)
        db.session.flush()  # Get the ID before committing
        
        # Add creator to room
        user_room = UserRoom(user_id=current_user.id, room_id=room.id)
        db.session.add(user_room)
        
        db.session.commit()
        
        flash(f'Room "{form.name.data}" created successfully!', 'success')
        return redirect(url_for('rooms'))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('rooms'))

# Join room route
@app.route('/rooms/join/<int:room_id>')
@login_required
def join_chat_room(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Check if user is already in room
    user_room = UserRoom.query.filter_by(user_id=current_user.id, room_id=room_id).first()
    if not user_room:
        user_room = UserRoom(user_id=current_user.id, room_id=room_id)
        db.session.add(user_room)
        db.session.commit()
        flash(f'You joined the room: {room.name}', 'success')
    
    return redirect(url_for('chat', room_id=room_id))

# Leave room route
@app.route('/rooms/leave/<int:room_id>')
@login_required
def leave_chat_room(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Check if user is in room
    user_room = UserRoom.query.filter_by(user_id=current_user.id, room_id=room_id).first()
    if user_room:
        db.session.delete(user_room)
        db.session.commit()
        flash(f'You left the room: {room.name}', 'success')
    
    return redirect(url_for('rooms'))

# Chat room route
@app.route('/chat/<int:room_id>')
@login_required
def chat(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Check if user is in room
    user_room = UserRoom.query.filter_by(user_id=current_user.id, room_id=room_id).first()
    if not user_room:
        flash('You need to join this room first.', 'warning')
        return redirect(url_for('rooms'))
    
    # Get messages from room with their reactions
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp).all()
    
    # Prepare message reactions data
    for message in messages:
        # Get reaction counts
        reaction_counts = {}
        for reaction in message.reactions.all():
            if reaction.reaction_type in reaction_counts:
                reaction_counts[reaction.reaction_type] += 1
            else:
                reaction_counts[reaction.reaction_type] = 1
        
        # Get user's reactions to this message
        user_reactions = []
        if current_user.is_authenticated:
            user_reactions = [r.reaction_type for r in message.reactions.filter_by(user_id=current_user.id).all()]
        
        # Attach to message object as attributes
        message.reactions = reaction_counts
        message.user_reactions = user_reactions
    
    # Count users in room
    room_members_count = UserRoom.query.filter_by(room_id=room_id).count()
    
    form = MessageForm()
    
    return render_template('chat.html', title=f'Chat - {room.name}', 
                          room=room, messages=messages, form=form,
                          room_members_count=room_members_count)

# Admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    # Get stats
    user_count = User.query.count()
    room_count = Room.query.count()
    message_count = Message.query.count()
    
    # Get recent users
    recent_users = User.query.order_by(User.date_joined.desc()).limit(5).all()
    
    # Get active rooms
    active_rooms = Room.query.join(Message).group_by(Room.id).order_by(db.func.count(Message.id).desc()).limit(5).all()
    
    # Get stats for verified vs unverified users
    verified_users = User.query.filter_by(is_verified=True).count()
    unverified_users = User.query.filter_by(is_verified=False).count()
    
    # Get last 24 hours message count
    recent_message_count = Message.query.filter(
        Message.timestamp > (datetime.utcnow() - timedelta(hours=24))
    ).count()
    
    return render_template('admin/dashboard.html', title='Admin Dashboard',
                          user_count=user_count, room_count=room_count, message_count=message_count,
                          recent_users=recent_users, active_rooms=active_rooms,
                          verified_users=verified_users, unverified_users=unverified_users,
                          recent_message_count=recent_message_count)

# Admin users
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    
    users = User.query.all()
    return render_template('admin/users.html', title='Manage Users', users=users)

# Admin user monitoring
@app.route('/admin/users/<int:user_id>/monitor')
@login_required
def admin_monitor_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Get user's messages with reactions
    messages = Message.query.filter_by(user_id=user_id).order_by(Message.timestamp.desc()).all()
    
    # Prepare message reactions data
    for message in messages:
        # Get reaction counts
        reaction_counts = {}
        for reaction in message.reactions.all():
            if reaction.reaction_type in reaction_counts:
                reaction_counts[reaction.reaction_type] += 1
            else:
                reaction_counts[reaction.reaction_type] = 1
        
        # Get user's reactions to this message
        user_reactions = []
        if current_user.is_authenticated:
            user_reactions = [r.reaction_type for r in message.reactions.filter_by(user_id=current_user.id).all()]
        
        # Attach to message object as attributes
        message.reactions = reaction_counts
        message.user_reactions = user_reactions
    
    # Get user's rooms
    user_rooms = UserRoom.query.filter_by(user_id=user_id).all()
    rooms = [user_room.room for user_room in user_rooms]
    
    return render_template('admin/monitor_user.html', title=f'Monitor User: {user.username}',
                          user=user, messages=messages, rooms=rooms)

# Admin toggle user admin status
@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow removing admin from self
    if user.id == current_user.id:
        flash('You cannot remove your own admin status.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    flash(f'Admin status updated for {user.username}.', 'success')
    return redirect(url_for('admin_users'))

# Admin delete user
@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting self
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Delete user's messages
    Message.query.filter_by(user_id=user.id).delete()
    
    # Delete user's room memberships
    UserRoom.query.filter_by(user_id=user.id).delete()
    
    # Get rooms created by user
    created_rooms = Room.query.filter_by(created_by=user.id).all()
    
    # Delete messages from rooms created by user
    for room in created_rooms:
        Message.query.filter_by(room_id=room.id).delete()
    
    # Delete user's rooms
    Room.query.filter_by(created_by=user.id).delete()
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} has been deleted.', 'success')
    return redirect(url_for('admin_users'))

# Admin rooms
@app.route('/admin/rooms')
@login_required
def admin_rooms():
    if not current_user.is_admin:
        abort(403)
    
    rooms = Room.query.all()
    return render_template('admin/rooms.html', title='Manage Rooms', rooms=rooms)

# Admin monitor room
@app.route('/admin/rooms/<int:room_id>/monitor')
@login_required
def admin_monitor_room(room_id):
    if not current_user.is_admin:
        abort(403)
    
    room = Room.query.get_or_404(room_id)
    
    # Get room messages with reactions
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.desc()).all()
    
    # Prepare message reactions data
    for message in messages:
        # Get reaction counts
        reaction_counts = {}
        for reaction in message.reactions.all():
            if reaction.reaction_type in reaction_counts:
                reaction_counts[reaction.reaction_type] += 1
            else:
                reaction_counts[reaction.reaction_type] = 1
        
        # Get user's reactions to this message
        user_reactions = []
        if current_user.is_authenticated:
            user_reactions = [r.reaction_type for r in message.reactions.filter_by(user_id=current_user.id).all()]
        
        # Attach to message object as attributes
        message.reactions = reaction_counts
        message.user_reactions = user_reactions
    
    # Get room members
    room_members = UserRoom.query.filter_by(room_id=room_id).all()
    members = [user_room.user for user_room in room_members]
    
    # Get message count per user in this room
    user_message_counts = db.session.query(
        User.username, 
        db.func.count(Message.id).label('message_count')
    ).join(Message).filter(
        Message.room_id == room_id
    ).group_by(User.username).order_by(
        db.desc('message_count')
    ).all()
    
    return render_template('admin/monitor_room.html', title=f'Monitor Room: {room.name}',
                          room=room, messages=messages, members=members,
                          user_message_counts=user_message_counts)

# Admin create room
@app.route('/admin/rooms/create', methods=['GET', 'POST'])
@login_required
def admin_create_room():
    if not current_user.is_admin:
        abort(403)
    
    form = CreateRoomForm()
    
    if form.validate_on_submit():
        room = Room(name=form.name.data, created_by=current_user.id)
        db.session.add(room)
        db.session.commit()
        
        flash(f'Room "{form.name.data}" created successfully!', 'success')
        return redirect(url_for('admin_rooms'))
    
    return render_template('admin/create_room.html', title='Create Room', form=form)

# Admin delete room
@app.route('/admin/rooms/<int:room_id>/delete', methods=['POST'])
@login_required
def delete_room(room_id):
    if not current_user.is_admin:
        abort(403)
    
    room = Room.query.get_or_404(room_id)
    
    # Don't allow deleting General room
    if room.name == 'General':
        flash('The General room cannot be deleted.', 'danger')
        return redirect(url_for('admin_rooms'))
    
    # Delete room's messages
    Message.query.filter_by(room_id=room.id).delete()
    
    # Delete room's user memberships
    UserRoom.query.filter_by(room_id=room.id).delete()
    
    # Delete room
    db.session.delete(room)
    db.session.commit()
    
    flash(f'Room {room.name} has been deleted.', 'success')
    return redirect(url_for('admin_rooms'))

# Socket.IO event handlers
@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{current_user.username} has joined the room.'}, room=room)

@socketio.on('leave')
def handle_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{current_user.username} has left the room.'}, room=room)

@socketio.on('message')
def handle_message(data):
    if not current_user.is_authenticated:
        return
    
    room_id = data['room']
    content = data['message']
    
    # Save message to database
    message = Message(
        content=content,
        user_id=current_user.id,
        room_id=room_id
    )
    db.session.add(message)
    db.session.commit()
    
    # Broadcast message to room
    emit('message', {
        'id': message.id,
        'username': current_user.username,
        'message': content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'reactions': {}
    }, room=room_id)

# Handle message reactions
@app.route('/api/messages/<int:message_id>/react', methods=['POST'])
@login_required
def react_to_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    # Get reaction type from request
    data = request.get_json()
    if not data or 'reaction_type' not in data:
        return jsonify({'error': 'Reaction type is required'}), 400
        
    reaction_type = data['reaction_type']
    
    # Validate reaction type (only allow certain emojis)
    allowed_reactions = ['like', 'heart', 'laugh', 'wow', 'sad', 'angry']
    if reaction_type not in allowed_reactions:
        return jsonify({'error': 'Invalid reaction type'}), 400
    
    # Check if user has already reacted with this type
    existing_reaction = MessageReaction.query.filter_by(
        user_id=current_user.id,
        message_id=message_id,
        reaction_type=reaction_type
    ).first()
    
    result = {}
    
    if existing_reaction:
        # User is removing their reaction
        db.session.delete(existing_reaction)
        db.session.commit()
        result['action'] = 'removed'
    else:
        # User is adding a new reaction
        reaction = MessageReaction(
            user_id=current_user.id,
            message_id=message_id,
            reaction_type=reaction_type
        )
        db.session.add(reaction)
        db.session.commit()
        result['action'] = 'added'
    
    # Get updated reaction counts
    reaction_counts = {}
    for reaction in message.reactions.all():
        if reaction.reaction_type in reaction_counts:
            reaction_counts[reaction.reaction_type] += 1
        else:
            reaction_counts[reaction.reaction_type] = 1
    
    # Get user's reactions to this message
    user_reactions = [r.reaction_type for r in message.reactions.filter_by(user_id=current_user.id).all()]
    
    result['reaction_counts'] = reaction_counts
    result['user_reactions'] = user_reactions
    
    # Broadcast reaction update to room
    socketio.emit('reaction_update', {
        'message_id': message_id,
        'reactions': reaction_counts,
        'user_reactions': user_reactions
    }, room=str(message.room_id))
    
    return jsonify(result)

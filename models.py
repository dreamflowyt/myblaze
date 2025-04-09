from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin, current_user

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    created_rooms = db.relationship('Room', backref='creator', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username}>'

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    messages = db.relationship('Message', backref='room', lazy='dynamic')
    
    def __repr__(self):
        return f'<Room {self.name}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    
    # Add relationship to reactions - add this after MessageReaction class is defined
    
    def __repr__(self):
        return f'<Message {self.id}>'
    
    def to_dict(self):
        # Group reactions by type with count
        reaction_counts = {}
        user_reactions = []
        
        # Only get reactions if the relationship exists (after MessageReaction model is defined)
        if hasattr(self, 'reactions'):
            for reaction in self.reactions.all():
                if reaction.reaction_type in reaction_counts:
                    reaction_counts[reaction.reaction_type] += 1
                else:
                    reaction_counts[reaction.reaction_type] = 1
            
            # Get current user's reactions to this message
            if hasattr(current_user, 'id') and current_user.is_authenticated:
                user_reactions = [r.reaction_type for r in self.reactions.filter_by(user_id=current_user.id).all()]
        
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'username': self.author.username,
            'room_id': self.room_id,
            'reactions': reaction_counts,
            'user_reactions': user_reactions
        }

class UserRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define unique constraint to prevent duplicates
    __table_args__ = (db.UniqueConstraint('user_id', 'room_id'),)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('rooms', lazy='dynamic'))
    room = db.relationship('Room', backref=db.backref('members', lazy='dynamic'))
    
# Message Reaction model
class MessageReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    reaction_type = db.Column(db.String(20), nullable=False)  # 'like', 'heart', 'laugh', etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Make sure a user can only react once with each reaction type to a message
    __table_args__ = (db.UniqueConstraint('user_id', 'message_id', 'reaction_type'),)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('reactions', lazy='dynamic'))
    
    def __repr__(self):
        return f'<MessageReaction {self.user_id} {self.reaction_type} {self.message_id}>'

# Now add the relationship to Message
Message.reactions = db.relationship('MessageReaction', backref='message', lazy='dynamic', cascade="all, delete-orphan")

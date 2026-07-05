import bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False) # Increased size for hash storage
    role = db.Column(db.String(20), default='user', nullable=False) # Added for authorization roles

    def set_password(self, plain_password):
        # Generate a salt and hash the password
        salt = bcrypt.gensalt()
        self.password = bcrypt.hashpw(plain_password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, plain_password):
        # Compare incoming plain text against the stored hash
        return bcrypt.checkpw(plain_password.encode('utf-8'), self.password.encode('utf-8'))

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
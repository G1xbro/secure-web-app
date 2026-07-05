import os
from flask import Flask, jsonify, request
from models import db, User, Note
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Create the database tables automatically
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return jsonify({"message": "Secure Web Application Baseline API Active"})

# Quick test route to check database functionality
@app.route('/api/test-user', methods=['POST'])
def create_test_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing fields"}), 400
        
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": f"User {data['username']} created successfully!"}), 201

if __name__ == '__main__':
    app.run(debug=True)
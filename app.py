import os
import datetime
import jwt
from flask import Flask, jsonify, request, g, render_template
from functools import wraps
from models import db, User, Note
from dotenv import load_dotenv
import html  # Standard Python library for XSS sanitization
from pydantic import BaseModel, Field, ValidationError
import logging

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db.init_app(app)

@app.route('/')
def index():
    # Serves the frontend application interface
    return render_template('index.html')

# --- SECURITY DECORATOR ---
def token_required(allowed_roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            
            # 1. Token Extraction
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                if auth_header.startswith("Bearer "):
                    token = auth_header.split(" ")[1]

            if not token:
                logging.warning(f"Unauthenticated request attempt missing token from IP: {request.remote_addr} on endpoint: {request.path}")
                return jsonify({"error": "Authentication token missing"}), 401

            # 2. Token Verification & Role Authorization
            try:
                # Verify token signature using the secret key
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = User.query.get(data['user_id'])
                
                if not current_user:
                    logging.warning(f"Valid token presented for non-existent User ID: {data.get('user_id')} from IP: {request.remote_addr}")
                    return jsonify({"error": "User no longer exists"}), 401
                
                # Check for Privilege Escalation Attempt
                if allowed_roles and current_user.role not in allowed_roles:
                    logging.warning(
                        f"SECURITY ALERT: User ID {current_user.id} ({current_user.role}) "
                        f"attempted unauthorized access to restricted endpoint: {request.path} (Allowed: {allowed_roles})"
                    )
                    return jsonify({"error": "Unauthorized access level"}), 403

                # Attach user context globally to the request context
                g.current_user = current_user

            except jwt.ExpiredSignatureError:
                logging.info(f"Expired token presented from IP: {request.remote_addr} on endpoint: {request.path}")
                return jsonify({"error": "Token has expired"}), 401
                
            except jwt.InvalidTokenError:
                logging.warning(f"INTRUSION DETECTED: Malicious or malformed JWT token attempt from IP: {request.remote_addr} on endpoint: {request.path}")
                return jsonify({"error": "Invalid token"}), 401

            return f(*args, **kwargs)
        return decorated
    return decorator

# --- DEFENSIVE LOGGING ENGINE CONFIGURATION ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] SECURITY_EVENT: %(message)s',
    handlers=[
        logging.FileHandler("security.log"), # Writes out to a secure local audit file
        logging.StreamHandler()              # Mirror outputs out to the system console
    ]
)

# --- REGISTRATION & LOGIN ROUTES ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing credentials"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already taken"}), 400

    new_user = User(username=data['username'])
    # Cleanly assign role if provided, otherwise defaults to 'user'
    if 'role' in data:
        new_user.role = data['role']
        
    new_user.set_password(data['password']) # Safe Hashing execution
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "Registration successful"}), 201


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        logging.warning(f"Malformed login request payload received from IP: {request.remote_addr}")
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter_by(username=data['username']).first()
    
    # DEFENSIVE LOGGING: Monitor failures safely without exposing data['password']
    if not user or not user.check_password(data['password']):
        logging.warning(
            f"AUTH FAILURE: Failed login attempt for username: '{data['username']}' "
            f"from origin IP: {request.remote_addr}"
        )
        return jsonify({"error": "Invalid username or password"}), 401

    # Issue a signed stateless JWT payload
    payload = {
        "user_id": user.id,
        "role": user.role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2) # Expires in 2 hours
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

    # Audit Trail: Track successful sessions for anomaly detection
    logging.info(f"AUTH SUCCESS: Session token generated for User ID: {user.id} ({user.role}) from IP: {request.remote_addr}")
    
    return jsonify({"token": token, "message": "Login successful"}), 200

# --- PROTECTED APPLICATION ROUTES ---

@app.route('/api/notes', methods=['GET'])
@token_required(allowed_roles=['user', 'admin'])
def get_notes():
    # Only pull notes belonging to the authenticated context
    user_notes = Note.query.filter_by(user_id=g.current_user.id).all()
    output = [{"id": n.id, "title": n.title, "content": n.content} for n in user_notes]
    return jsonify({"notes": output}), 200


# --- UPDATED & SECURED NOTE ROUTES ---

@app.route('/api/notes', methods=['POST'])
@token_required(allowed_roles=['user', 'admin'])
def create_note():
    # 1. Catch malformed JSON requests
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON context"}), 400
        
    # 2. Strict type-checking and length restriction via Pydantic
    try:
        validated_data = NoteCreateSchema(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation failed", "details": e.errors()}), 422

    # 3. Defensive XSS Mitigation: HTML-escape incoming user strings
    clean_title = html.escape(validated_data.title)
    clean_content = html.escape(validated_data.content)

    # 4. Save to database tied strictly to the current session user
    new_note = Note(
        title=clean_title,
        content=clean_content,
        user_id=g.current_user.id
    )
    db.session.add(new_note)
    db.session.commit()

    return jsonify({"message": "Note created securely", "note_id": new_note.id}), 201

@app.route('/api/notes/<int:note_id>', methods=['GET'])
@token_required(allowed_roles=['user', 'admin'])
def get_note_by_id(note_id):
    # Fetch target record
    note = Note.query.get(note_id)
    if not note:
        return jsonify({"error": "Note not found"}), 404

    # Anti-IDOR / BOLA Check: Crucial check to ensure users can't snooping around
    if note.user_id != g.current_user.id and g.current_user.role != 'admin':
        return jsonify({"error": "Access denied: Unauthorized ownership record"}), 403

    return jsonify({"id": note.id, "title": note.title, "content": note.content}), 200



@app.route('/api/admin/dashboard', methods=['GET'])
@token_required(allowed_roles=['admin'])
def admin_dashboard():
    # Strict role restriction check verified via middleware
    total_users = User.query.count()
    return jsonify({"message": "Welcome Admin", "metrics": {"total_registered_users": total_users}}), 200

# --- INPUT VALIDATION SCHEMA (Anti-XSS / Integrity) ---
class NoteCreateSchema(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    content: str = Field(..., min_length=1, max_length=2000)

@app.after_request
def add_security_headers(response):
    # Prevent Clickjacking by blocking the app from being rendered inside an iframe
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Block browsers from sniffing MIME types away from what the server declares
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Restrict where resources (JS/CSS) can load from (Basic CSP)
    response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none';"
    
    # Force client browsers to strict HTTPS communication channels
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
from flask import Flask, request, jsonify, session
from flask_cors import CORS
import sqlite3
import hashlib
from datetime import datetime, timedelta
import os
from collections import Counter
import re
import math
from functools import wraps
import time
import schedule
import threading
from werkzeug.utils import secure_filename
import pytz  # Add this import for timezone handling
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache

app = Flask(__name__)

# Single CORS configuration (remove duplicate configurations)
CORS(app, 
    resources={r"/*": {
        "origins": ["http://127.0.0.1:8000", "http://localhost:8000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 600
    }}
)

app.secret_key = "your_secret_key"

# Session configuration
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_COOKIE_PATH='/',
    SESSION_COOKIE_DOMAIN=None
)

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Add debug configuration at the top with other app configurations
app.config['DEBUG'] = True

@app.before_request
def before_request():
    session.permanent = True
    session.modified = True

# Add a test endpoint
@app.route('/', methods=['GET', 'OPTIONS'])
def test_connection():
    return jsonify({"message": "Server is running"}), 200

# Database initialization
def init_db():
    conn = sqlite3.connect('database/scanner.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            credits INTEGER DEFAULT 20,
            last_reset DATE
        )
    ''')
    
    # Create initial admin user if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_password = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role, credits) VALUES (?, ?, ?, ?)",
                 ("admin", hashed_password, "admin", 100))
    
    # Create documents table
    c.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create credit requests table
    c.execute('''
        CREATE TABLE IF NOT EXISTS credit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Add document_vectors table
    c.execute('''
        CREATE TABLE IF NOT EXISTS document_vectors (
            doc_id INTEGER PRIMARY KEY,
            word_vector TEXT NOT NULL,
            FOREIGN KEY (doc_id) REFERENCES documents (id)
        )
    ''')
    
    # Add credit_transactions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS credit_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
if not os.path.exists('database'):
    os.makedirs('database')
init_db()

# Helper function to get database connection
def get_db():
    conn = sqlite3.connect('database/scanner.db', timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

# Update the text processing functions
def preprocess_text(text):
    try:
        # Convert to lowercase and split into words
        words = re.findall(r'\w+', text.lower())
        
        # Expanded stop words list
        stop_words = set([
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
            'this', 'that', 'these', 'those', 'with', 'from', 'by', 'of'
        ])
        
        # Remove stop words and short words
        words = [w for w in words if w not in stop_words and len(w) > 2]
        
        return words
    except Exception as e:
        print(f"Error preprocessing text: {e}")
        return []

def create_vector(text):
    try:
        words = preprocess_text(text)
        if not words:
            return None
            
        # Create TF (Term Frequency) vector
        vector = dict(Counter(words))
        
        # Normalize the vector
        total_words = sum(vector.values())
        if total_words > 0:
            for word in vector:
                vector[word] = vector[word] / total_words
                
        return vector
    except Exception as e:
        print(f"Error creating vector: {e}")
        return None

# Update the cosine_similarity function to handle string vectors properly
def cosine_similarity(vec1, vec2):
    """Calculate cosine similarity between two vectors"""
    try:
        # Ensure we're working with dictionaries
        if isinstance(vec1, str):
            vec1 = eval(vec1)
        if isinstance(vec2, str):
            vec2 = eval(vec2)
            
        # Get all unique words
        all_words = set(vec1.keys()) | set(vec2.keys())
        
        # Calculate dot product and magnitudes
        dot_product = sum(vec1.get(word, 0) * vec2.get(word, 0) for word in all_words)
        mag1 = math.sqrt(sum(vec1.get(word, 0) ** 2 for word in all_words))
        mag2 = math.sqrt(sum(vec2.get(word, 0) ** 2 for word in all_words))
        
        # Avoid division by zero
        if mag1 * mag2 == 0:
            return 0.0
            
        return dot_product / (mag1 * mag2)
    except Exception as e:
        print(f"Error calculating similarity: {str(e)}")
        return 0.0

# Update the format_datetime function
def format_datetime(dt_str):
    """Convert datetime string to formatted datetime"""
    try:
        if isinstance(dt_str, str):
            # Try different date formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    dt = datetime.strptime(dt_str, fmt)
                    break
                except ValueError:
                    continue
        else:
            dt = dt_str
            
        # Get current timezone
        local_tz = datetime.now().astimezone().tzinfo
        
        # Convert to local timezone if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC).astimezone(local_tz)
            
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Date formatting error: {str(e)} for {dt_str}")
        return str(dt_str)

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, role, credits) VALUES (?, ?, ?, ?)",
                 (username, hashed_password, "user", 20))
        conn.commit()
        return jsonify({"message": "Registration successful"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    finally:
        conn.close()

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    expected_role = data.get("expected_role")
    
    if not username or not password or not expected_role:
        return jsonify({"error": "Username, password and role are required"}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Use parameterized query instead of string concatenation
        c.execute("""
            SELECT id, username, role, credits 
            FROM users 
            WHERE username = ? AND password = ?
        """, (username, hashlib.sha256(password.encode()).hexdigest()))
        
        user = c.fetchone()
        
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401

        # Then verify role matches
        if user['role'] != expected_role:
            return jsonify({"error": "Invalid credentials for selected role"}), 403
        
        # If everything matches, proceed with login
        session.clear()
        session.permanent = True
        session['user'] = username
        
        return jsonify({
            "message": "Login successful",
            "username": username,
            "role": user["role"],
            "credits": user["credits"]
        })
        
    except Exception as e:
        print("Login error:", str(e))
        return jsonify({"error": "Login failed"}), 500
    finally:
        conn.close()

# User logout
@app.route('/auth/logout', methods=['POST'])
def logout():
    session.pop("user", None)
    return jsonify({"message": "Logged out successfully"})

# Move the reset_user_credits function definition before the scheduler initialization
def reset_user_credits():
    """Reset all users' credits to 20 at 2 AM"""
    conn = get_db()
    c = conn.cursor()
    try:
        # Get current time in UTC
        now = datetime.now(pytz.UTC)
        
        # Update all non-admin users' credits
        c.execute("""
            UPDATE users 
            SET credits = 20, 
                last_reset = ? 
            WHERE role != 'admin' AND (
                last_reset IS NULL OR 
                DATE(last_reset) < DATE(?)
            )
        """, (now, now))
        
        # Log credit resets for affected users
        c.execute("""
            INSERT INTO credit_transactions (user_id, amount, transaction_type, transaction_date)
            SELECT id, 20, 'daily_reset', ?
            FROM users
            WHERE role != 'admin' AND (
                last_reset IS NULL OR 
                DATE(last_reset) < DATE(?)
            )
        """, (now, now))
        
        conn.commit()
        print(f"Daily credit reset completed at {now}")
    except Exception as e:
        print(f"Error in credit reset: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

# Now initialize the scheduler after the function is defined
scheduler = BackgroundScheduler()
scheduler.add_job(
    reset_user_credits,  # Function name
    trigger=CronTrigger(hour=2, minute=0),  # Run at 2 AM
    id='credit_reset',
    name='Daily credit reset at 2 AM',
    replace_existing=True
)

# Add credit logging
def log_credit_transaction(user_id, amount, transaction_type, conn=None):
    """Log credit transactions"""
    should_close = conn is None
    if conn is None:
        conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute("""
            INSERT INTO credit_transactions 
            (user_id, amount, transaction_type, transaction_date)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (user_id, amount, transaction_type))
        
        if should_close:
            conn.commit()
    except Exception as e:
        print(f"Error logging transaction: {e}")
        if should_close:
            conn.rollback()
    finally:
        if should_close:
            conn.close()

# Modify the get_credits route to include reset check
@app.route('/user/credits', methods=['GET'])
def get_credits():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Check for daily reset
    reset_daily_credits()
        
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT credits, last_reset FROM users WHERE username = ?", (session['user'],))
    user = c.fetchone()
    conn.close()
    
    return jsonify({
        "credits": user['credits'],
        "last_reset": user['last_reset']
    })

@app.route('/credits/request', methods=['POST'])
def request_credits():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
        
    data = request.get_json()
    amount = data.get('amount', 20)  # Default to 20 credits
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Get user_id
        c.execute("SELECT id FROM users WHERE username = ?", (session['user'],))
        user = c.fetchone()
        
        # Use current timestamp in UTC
        current_time = datetime.now(pytz.UTC)
        
        c.execute("""
            INSERT INTO credit_requests (user_id, amount, request_date)
            VALUES (?, ?, ?)
        """, (user['id'], amount, current_time))
        
        conn.commit()
        return jsonify({"message": "Credit request submitted successfully"})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Failed to submit request"}), 500
    finally:
        conn.close()

class DocumentMatcher:
    def __init__(self):
        self.stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 
            'for', 'is', 'are', 'was', 'were'
        }
        
    def preprocess_text(self, text):
        """Clean and tokenize text"""
        # Convert to lowercase and split into words
        words = re.findall(r'\w+', text.lower())
        # Remove stop words and short words
        return [w for w in words if w not in self.stop_words and len(w) > 2]
    
    def cosine_similarity(self, vec1, vec2):
        """Calculate cosine similarity between two vectors"""
        if isinstance(vec1, str):
            vec1 = eval(vec1)
        if isinstance(vec2, str):
            vec2 = eval(vec2)
            
        intersection = set(vec1.keys()) & set(vec2.keys())
        numerator = sum(vec1[x] * vec2[x] for x in intersection)
        
        sum1 = sum(vec1[x]**2 for x in vec1.keys())
        sum2 = sum(vec2[x]**2 for x in vec2.keys())
        denominator = math.sqrt(sum1) * math.sqrt(sum2)
        
        return 0.0 if denominator == 0 else numerator / denominator
    
    def jaccard_similarity(self, vec1, vec2):
        """Calculate Jaccard similarity between two vectors"""
        if isinstance(vec1, str):
            vec1 = eval(vec1)
        if isinstance(vec2, str):
            vec2 = eval(vec2)
            
        set1 = set(vec1.keys())
        set2 = set(vec2.keys())
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return 0.0 if union == 0 else intersection / union
    
    def get_best_similarity(self, vec1, vec2):
        """Get the best similarity score from all algorithms"""
        scores = {
            'cosine': self.cosine_similarity(vec1, vec2),
            'jaccard': self.jaccard_similarity(vec1, vec2)
        }
        
        best_score = max(scores.items(), key=lambda x: x[1])
        return {
            'score': best_score[1],
            'algorithm': best_score[0]
        }

# Update file upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB limit

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize limiter
limiter = Limiter(
    get_remote_address,  # Pass key_func directly
    app=app,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"],
    strategy="fixed-window"  # Add this line
)

@app.route('/scan/upload', methods=['POST'])
@limiter.limit("20 per minute")
def upload_document():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401

    if 'document' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['document']
    if not file or file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith('.txt'):
        return jsonify({"error": "Only .txt files are allowed"}), 400

    conn = get_db()
    c = conn.cursor()

    try:
        # Get user info
        c.execute("SELECT id, credits FROM users WHERE username = ?", (session['user'],))
        user = c.fetchone()

        if user['credits'] <= 0:
            return jsonify({"error": "Not enough credits"}), 403

        # Read and process the file
        content = file.read().decode('utf-8')
        word_vector = create_vector(content)

        # Save document
        c.execute("""
            INSERT INTO documents (user_id, filename, content, upload_date)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (user['id'], file.filename, content))
        
        doc_id = c.lastrowid

        # Save document vector
        if word_vector:
            c.execute("""
                INSERT INTO document_vectors (doc_id, word_vector)
                VALUES (?, ?)
            """, (doc_id, str(word_vector)))

        # Deduct credit
        c.execute("""
            UPDATE users 
            SET credits = credits - 1 
            WHERE id = ?
        """, (user['id'],))

        # Find similar documents
        c.execute("""
            SELECT d.id, d.filename, d.content, dv.word_vector
            FROM documents d
            JOIN document_vectors dv ON d.id = dv.doc_id
            WHERE d.user_id = ? AND d.id != ?
        """, (user['id'], doc_id))

        similar_docs = []
        for doc in c.fetchall():
            if doc['word_vector']:
                similarity = cosine_similarity(word_vector, doc['word_vector'])
                if similarity > 0.3:
                    similar_docs.append({
                        "id": doc['id'],
                        "filename": doc['filename'],
                        "similarity": round(similarity * 100, 2),
                        "preview": doc['content'][:200] + '...' if len(doc['content']) > 200 else doc['content']
                    })

        similar_docs.sort(key=lambda x: x['similarity'], reverse=True)

        conn.commit()

        return jsonify({
            "message": "Document uploaded successfully",
            "credits_remaining": user['credits'] - 1,
            "similar_documents": similar_docs[:5]
        })

    except Exception as e:
        conn.rollback()
        print("Upload error:", str(e))
        return jsonify({"error": "Failed to upload document"}), 500
    finally:
        conn.close()

# Add a route to check session status
@app.route('/auth/check', methods=['GET'])
def check_auth():
    print(f"Checking auth. Session: {session}")  # Debug print
    if 'user' in session:
        return jsonify({"authenticated": True, "user": session['user']}), 200
    return jsonify({"authenticated": False}), 401

# Add this new route
@app.route('/documents/history', methods=['GET'])
def get_document_history():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Get user_id first
        c.execute("SELECT id FROM users WHERE username = ?", (session['user'],))
        user = c.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Get documents for this user
        c.execute("""
            SELECT 
                d.id,
                d.filename,
                d.content,
                d.upload_date,
                dv.word_vector
            FROM documents d
            LEFT JOIN document_vectors dv ON d.id = dv.doc_id
            WHERE d.user_id = ?
            ORDER BY d.upload_date DESC
        """, (user['id'],))
        
        documents = []
        for doc in c.fetchall():
            # Create a preview of the content (first 200 characters)
            preview = doc['content'][:200] + '...' if len(doc['content']) > 200 else doc['content']
            
            documents.append({
                "id": doc['id'],
                "filename": doc['filename'],
                "preview": preview,
                "upload_date": doc['upload_date'],
                "word_vector": doc['word_vector']
            })
        
        return jsonify({"documents": documents})
        
    except Exception as e:
        print("Error fetching document history:", str(e))
        return jsonify({"error": "Failed to fetch document history"}), 500
    finally:
        conn.close()

@app.route('/documents/<int:doc_id>/similar', methods=['GET'])
def get_similar_documents(doc_id):
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # First verify the document belongs to the user and get its vector
        c.execute("""
            SELECT d.id, dv.word_vector
            FROM documents d
            LEFT JOIN document_vectors dv ON d.id = dv.doc_id
            JOIN users u ON d.user_id = u.id
            WHERE d.id = ? AND u.username = ?
        """, (doc_id, session['user']))
        
        source_doc = c.fetchone()
        if not source_doc:
            return jsonify({"error": "Document not found"}), 404
            
        if not source_doc['word_vector']:
            return jsonify({"similar_documents": []}), 200
        
        # Get all other documents from the same user
        c.execute("""
            SELECT 
                d.id, 
                d.filename, 
                d.content, 
                dv.word_vector
            FROM documents d
            LEFT JOIN document_vectors dv ON d.id = dv.doc_id
            JOIN users u ON d.user_id = u.id
            WHERE u.username = ? 
            AND d.id != ?
            AND dv.word_vector IS NOT NULL
        """, (session['user'], doc_id))
        
        similar_docs = []
        source_vector = eval(source_doc['word_vector'])
        
        for doc in c.fetchall():
            try:
                if doc['word_vector']:
                    target_vector = eval(doc['word_vector'])
                    similarity = cosine_similarity(source_vector, target_vector)
                    if similarity > 0.3:  # Only include if similarity is above threshold
                        similar_docs.append({
                            "id": doc['id'],
                            "filename": doc['filename'],
                            "similarity": round(similarity * 100, 2),
                            "preview": doc['content'][:200] + '...' if len(doc['content']) > 200 else doc['content']
                        })
            except Exception as e:
                print(f"Error calculating similarity for doc {doc['id']}: {str(e)}")
                continue
        
        # Sort by similarity descending
        similar_docs.sort(key=lambda x: x['similarity'], reverse=True)
        
        return jsonify({
            "similar_documents": similar_docs[:5]  # Return top 5 similar documents
        })
        
    except Exception as e:
        print("Error finding similar documents:", str(e))
        return jsonify({"error": "Failed to find similar documents"}), 500
    finally:
        conn.close()

# Add these new admin routes
@app.route('/admin/credit-requests', methods=['GET'])
def get_credit_requests():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Check if user is admin
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username = ?", (session['user'],))
    user = c.fetchone()
    
    if user['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    # Get all pending requests with usernames
    c.execute("""
        SELECT cr.id, cr.amount, cr.request_date, cr.status, u.username
        FROM credit_requests cr
        JOIN users u ON cr.user_id = u.id
        WHERE cr.status = 'pending'
        ORDER BY cr.request_date DESC
    """)
    
    requests = []
    for row in c.fetchall():
        requests.append({
            "id": row['id'],
            "username": row['username'],
            "amount": row['amount'],
            "request_date": format_datetime(row['request_date'])
        })
    
    conn.close()
    return jsonify({"requests": requests})

@app.route('/admin/credit-requests/<int:request_id>', methods=['POST'])
def handle_credit_request(request_id):
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
        
    # Verify admin and process request
    data = request.json
    action = data.get('action')
    
    conn = get_db()
    c = conn.cursor()
    
    if action == 'approve':
        # Get request details
        c.execute("""
            SELECT cr.user_id, cr.amount, u.credits
            FROM credit_requests cr
            JOIN users u ON cr.user_id = u.id
            WHERE cr.id = ?
        """, (request_id,))
        req = c.fetchone()
        
        # Update user credits and request status
        c.execute("""
            UPDATE users 
            SET credits = credits + ?
            WHERE id = ?
        """, (req['amount'], req['user_id']))
        
        c.execute("""
            UPDATE credit_requests
            SET status = 'approved'
            WHERE id = ?
        """, (request_id,))
        
    elif action == 'deny':
        c.execute("""
            UPDATE credit_requests
            SET status = 'denied'
            WHERE id = ?
        """, (request_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"Request {action}d successfully"})

# Add this new route for user management
@app.route('/admin/users', methods=['GET'])
def get_users():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Check if user is admin
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username = ?", (session['user'],))
    user = c.fetchone()
    
    if user['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    # Get all users
    c.execute("""
        SELECT id, username, role, credits, last_reset
        FROM users
        ORDER BY username
    """)
    
    users = []
    for row in c.fetchall():
        users.append({
            "id": row['id'],
            "username": row['username'],
            "role": row['role'],
            "credits": row['credits'],
            "last_reset": row['last_reset']
        })
    
    conn.close()
    return jsonify({"users": users})

def validate_input(data, required_fields=None, field_types=None):
    """Validate input data against required fields and types"""
    if required_fields:
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
    
    if field_types:
        for field, expected_type in field_types.items():
            if field in data and not isinstance(data[field], expected_type):
                raise ValueError(f"Field {field} must be of type {expected_type.__name__}")
    
    return True

@app.route('/admin/update-credits', methods=['POST'])
def update_user_credits():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Verify admin
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username = ?", (session['user'],))
    admin = c.fetchone()
    
    if admin['role'] != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.get_json()
    try:
        validate_input(
            data,
            required_fields=['userId', 'credits'],
            field_types={'userId': int, 'credits': int}
        )
        user_id = data['userId']
        new_credits = data['credits']
        
        # Use parameterized query for update
        c.execute("""
            UPDATE users 
            SET credits = ? 
            WHERE id = ?
        """, (new_credits, user_id))
        
        conn.commit()
        return jsonify({"message": "Credits updated successfully"})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# Add this new route for deleting users
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Verify admin
    conn = get_db()
    c = conn.cursor()
    
    # Check if requester is admin
    c.execute("SELECT role FROM users WHERE username = ?", (session['user'],))
    admin = c.fetchone()
    if admin['role'] != 'admin':
        conn.close()
        return jsonify({"error": "Unauthorized"}), 403
    
    # Check if trying to delete admin
    c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    target_user = c.fetchone()
    if target_user and target_user['role'] == 'admin':
        conn.close()
        return jsonify({"error": "Cannot delete admin user"}), 403
    
    try:
        # Delete user's documents
        c.execute("DELETE FROM documents WHERE user_id = ?", (user_id,))
        
        # Delete user's credit requests
        c.execute("DELETE FROM credit_requests WHERE user_id = ?", (user_id,))
        
        # Delete the user
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        conn.close()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        conn.close()
        return jsonify({"error": "Failed to delete user"}), 500

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({"error": "Not logged in"}), 401
            
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE username = ?", (session['user'],))
        user = c.fetchone()
        conn.close()
        
        if not user or user['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
            
        return f(*args, **kwargs)
    return decorated_function

# Add these new routes for analytics
@app.route('/admin/analytics', methods=['GET'])
@cache.cached(timeout=300)  # Cache for 5 minutes
@admin_required
def get_analytics():
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Use parameterized queries for date ranges
        c.execute("""
            SELECT 
                DATE(upload_date) as scan_date,
                COUNT(*) as scan_count
            FROM documents
            WHERE upload_date >= DATE('now', '-30 days')
            GROUP BY DATE(upload_date)
            ORDER BY scan_date
        """)
        
        # Get scans per user per day
        daily_scans = c.fetchall()
        
        # Get top users by scan count
        c.execute("""
            SELECT u.username, COUNT(*) as total_scans
            FROM documents d
            JOIN users u ON d.user_id = u.id
            GROUP BY u.username
            ORDER BY total_scans DESC
            LIMIT 5
        """)
        top_users = c.fetchall()
        
        # Get credit usage statistics
        c.execute("""
            SELECT 
                u.username,
                u.credits as current_credits,
                COUNT(d.id) as documents_scanned,
                COUNT(cr.id) as credit_requests
            FROM users u
            LEFT JOIN documents d ON u.id = d.user_id
            LEFT JOIN credit_requests cr ON u.id = cr.user_id
            GROUP BY u.username
        """)
        credit_stats = c.fetchall()
        
        # Get common document topics (based on word frequency)
        c.execute("""
            SELECT word_vector
            FROM document_vectors
            ORDER BY doc_id DESC
            LIMIT 100
        """)
        recent_vectors = c.fetchall()
        
        # Process word vectors to find common topics
        common_words = {}
        for row in recent_vectors:
            vector = eval(row['word_vector'])
            for word, count in vector.items():
                if len(word) > 3:  # Skip short words
                    common_words[word] = common_words.get(word, 0) + count
        
        # Get top 10 common words
        top_topics = sorted(common_words.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Add pending requests count
        c.execute("""
            SELECT COUNT(*) as pending_count
            FROM credit_requests
            WHERE status = 'pending'
        """)
        pending_count = c.fetchone()['pending_count']
        
        return jsonify({
            "daily_scans": [dict(row) for row in daily_scans],
            "top_users": [dict(row) for row in top_users],
            "credit_stats": [dict(row) for row in credit_stats],
            "common_topics": [{"word": word, "count": count} for word, count in top_topics],
            "pending_requests": pending_count
        })
        
    except Exception as e:
        print("Analytics error:", e)
        return jsonify({"error": "Failed to generate analytics"}), 500
    finally:
        conn.close()

@app.route('/documents/clear', methods=['DELETE'])
def clear_documents():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Get user ID
        c.execute("SELECT id FROM users WHERE username = ?", (session['user'],))
        user = c.fetchone()
        
        # Delete user's document vectors
        c.execute("""
            DELETE FROM document_vectors 
            WHERE doc_id IN (
                SELECT id FROM documents WHERE user_id = ?
            )
        """, (user['id'],))
        
        # Delete user's documents
        c.execute("DELETE FROM documents WHERE user_id = ?", (user['id'],))
        
        conn.commit()
        return jsonify({"message": "Document history cleared successfully"})
        
    except Exception as e:
        conn.rollback()
        print("Error clearing documents:", e)
        return jsonify({"error": "Failed to clear document history"}), 500
    finally:
        conn.close()

@app.route('/documents/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Verify document belongs to user
        c.execute("""
            SELECT d.id 
            FROM documents d
            JOIN users u ON d.user_id = u.id
            WHERE d.id = ? AND u.username = ?
        """, (doc_id, session['user']))
        
        if not c.fetchone():
            return jsonify({"error": "Document not found or unauthorized"}), 404
        
        # Delete document vector
        c.execute("DELETE FROM document_vectors WHERE doc_id = ?", (doc_id,))
        
        # Delete document
        c.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        
        conn.commit()
        return jsonify({"message": "Document deleted successfully"})
        
    except Exception as e:
        conn.rollback()
        print("Error deleting document:", e)
        return jsonify({"error": "Failed to delete document"}), 500
    finally:
        conn.close()

class DocumentMatcher:
    def __init__(self):
        self.algorithms = {
            'cosine': self.cosine_similarity,
            'jaccard': self.jaccard_similarity,
            'levenshtein': self.levenshtein_distance
        }

def rate_limit(max_requests=100, window=60):
    """Rate limiting decorator"""
    requests = {}
    
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            now = time.time()
            # Implement rate limiting logic
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/user/profile', methods=['GET'])
def get_profile():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
        
    conn = get_db()
    c = conn.cursor()
    
    try:
        c.execute("""
            SELECT username, credits, last_reset,
                   (SELECT COUNT(*) FROM documents WHERE user_id = users.id) as total_scans
            FROM users 
            WHERE username = ?
        """, (session['user'],))
        
        user = c.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Calculate next reset time (2 AM next day)
        now = datetime.now()
        next_reset = now.replace(hour=2, minute=0, second=0, microsecond=0)
        
        # If it's past 2 AM, set for next day
        if now >= next_reset:
            next_reset += timedelta(days=1)
            
        time_until_reset = next_reset - now
        hours_until = int(time_until_reset.total_seconds() // 3600)
        minutes_until = int((time_until_reset.total_seconds() % 3600) // 60)
        
        if hours_until >= 24:
            next_reset_str = f"Tomorrow at 2 AM ({hours_until}h {minutes_until}m remaining)"
        else:
            next_reset_str = f"Today at 2 AM ({hours_until}h {minutes_until}m remaining)"
            
        return jsonify({
            "username": user['username'],
            "credits": user['credits'],
            "total_scans": user['total_scans'],
            "last_reset": format_datetime(user['last_reset']) if user['last_reset'] else None,
            "next_reset": next_reset_str,
            "next_reset_timestamp": next_reset.timestamp()
        })
        
    except Exception as e:
        print("Error fetching profile:", str(e))
        return jsonify({"error": "Failed to fetch profile"}), 500
    finally:
        conn.close()

@app.route('/documents/export', methods=['GET'])
def export_documents():
    if 'user' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn = get_db()
    c = conn.cursor()
    
    try:
        # Get user details
        c.execute("""
            SELECT id, username, credits, role, last_reset,
                   (SELECT COUNT(*) FROM documents WHERE user_id = users.id) as total_docs
            FROM users 
            WHERE username = ?
        """, (session['user'],))
        
        user = c.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Get documents with their vectors
        c.execute("""
            SELECT 
                d.id,
                d.filename,
                d.content,
                d.upload_date,
                dv.word_vector
            FROM documents d
            LEFT JOIN document_vectors dv ON d.id = dv.doc_id
            WHERE d.user_id = ?
            ORDER BY d.upload_date DESC
        """, (user['id'],))
        
        documents = c.fetchall()
        
        # Process documents and find similarities
        processed_docs = []
        for doc in documents:
            # Find similar documents for this document
            similar_docs = []
            if doc['word_vector']:
                c.execute("""
                    SELECT d2.id, d2.filename, dv2.word_vector
                    FROM documents d2
                    JOIN document_vectors dv2 ON d2.id = dv2.doc_id
                    WHERE d2.user_id = ? AND d2.id != ?
                """, (user['id'], doc['id']))
                
                for other_doc in c.fetchall():
                    similarity = cosine_similarity(doc['word_vector'], other_doc['word_vector'])
                    if similarity > 0.3:  # Similarity threshold
                        similar_docs.append({
                            'filename': other_doc['filename'],
                            'similarity': round(similarity * 100, 2)
                        })
            
            processed_docs.append({
                "id": doc['id'],
                "filename": doc['filename'],
                "content": doc['content'],
                "upload_date": format_datetime(doc['upload_date']),
                "similar_documents": sorted(similar_docs, key=lambda x: x['similarity'], reverse=True)
            })

        # Get credit transactions
        c.execute("""
            SELECT amount, transaction_type, transaction_date
            FROM credit_transactions
            WHERE user_id = ?
            ORDER BY transaction_date DESC
        """, (user['id'],))
        
        transactions = c.fetchall() or []

        return jsonify({
            "user_info": {
                "username": user['username'],
                "role": user['role'],
                "current_credits": user['credits'],
                "total_documents": user['total_docs'],
                "last_reset": format_datetime(user['last_reset']) if user['last_reset'] else None
            },
            "documents": processed_docs,
            "credit_history": [{
                "amount": trans['amount'],
                "type": trans['transaction_type'],
                "date": format_datetime(trans['transaction_date'])
            } for trans in transactions],
            "export_date": format_datetime(datetime.now())
        })
        
    except Exception as e:
        print("Error exporting documents:", str(e))
        return jsonify({"error": "Failed to export documents"}), 500
    finally:
        conn.close()

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Add new similarity functions
def jaccard_similarity(vec1, vec2):
    """Calculate Jaccard similarity between two vectors"""
    try:
        # Convert string vectors to sets of words
        if isinstance(vec1, str):
            vec1 = set(eval(vec1).keys())
        if isinstance(vec2, str):
            vec2 = set(eval(vec2).keys())
            
        # Calculate Jaccard similarity
        intersection = len(vec1.intersection(vec2))
        union = len(vec1.union(vec2))
        
        return intersection / union if union > 0 else 0.0
    except Exception as e:
        print(f"Error calculating Jaccard similarity: {str(e)}")
        return 0.0

def levenshtein_distance(text1, text2):
    """Calculate normalized Levenshtein distance"""
    try:
        # Get words from vectors
        if isinstance(text1, str):
            text1 = ' '.join(eval(text1).keys())
        if isinstance(text2, str):
            text2 = ' '.join(eval(text2).keys())
            
        # Calculate Levenshtein distance
        m, n = len(text1), len(text2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
            
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if text1[i-1] == text2[j-1] else 1
                dp[i][j] = min(dp[i-1][j] + 1,        # deletion
                              dp[i][j-1] + 1,        # insertion
                              dp[i-1][j-1] + cost)   # substitution
                
        # Normalize the distance
        max_len = max(m, n)
        return 1 - (dp[m][n] / max_len if max_len > 0 else 0)
    except Exception as e:
        print(f"Error calculating Levenshtein distance: {str(e)}")
        return 0.0

def tfidf_similarity(vec1, vec2):
    """Calculate TF-IDF based similarity"""
    try:
        # Convert string vectors to dictionaries
        if isinstance(vec1, str):
            vec1 = eval(vec1)
        if isinstance(vec2, str):
            vec2 = eval(vec2)
            
        # Get all unique words
        all_words = set(vec1.keys()) | set(vec2.keys())
        
        # Calculate document frequencies
        doc_freq = {}
        for word in all_words:
            doc_freq[word] = (word in vec1) + (word in vec2)
            
        # Calculate TF-IDF vectors
        vec1_tfidf = {word: freq * math.log(2/doc_freq[word]) 
                      for word, freq in vec1.items()}
        vec2_tfidf = {word: freq * math.log(2/doc_freq[word]) 
                      for word, freq in vec2.items()}
        
        # Calculate cosine similarity with TF-IDF weights
        dot_product = sum(vec1_tfidf.get(word, 0) * vec2_tfidf.get(word, 0) 
                         for word in all_words)
        mag1 = math.sqrt(sum(v*v for v in vec1_tfidf.values()))
        mag2 = math.sqrt(sum(v*v for v in vec2_tfidf.values()))
        
        return dot_product / (mag1 * mag2) if mag1 * mag2 > 0 else 0.0
    except Exception as e:
        print(f"Error calculating TF-IDF similarity: {str(e)}")
        return 0.0

@app.route('/test/similarity', methods=['POST'])
def test_similarity():
    """Test endpoint to compare two texts using different algorithms"""
    try:
        data = request.get_json()
        text1 = data.get('text1', '')
        text2 = data.get('text2', '')
        algorithm = data.get('algorithm', 'all')
        
        if not text1 or not text2:
            return jsonify({"error": "Both texts are required"}), 400
            
        # Create vectors
        vec1 = create_vector(text1)
        vec2 = create_vector(text2)
        
        results = {}
        
        # Test specific algorithm or all
        if algorithm == 'all':
            results = {
                'cosine': round(cosine_similarity(vec1, vec2) * 100, 2),
                'jaccard': round(jaccard_similarity(vec1, vec2) * 100, 2),
                'levenshtein': round(levenshtein_distance(text1, text2) * 100, 2),
                'tfidf': round(tfidf_similarity(vec1, vec2) * 100, 2)
            }
        else:
            similarity_functions = {
                'cosine': cosine_similarity,
                'jaccard': jaccard_similarity,
                'levenshtein': levenshtein_distance,
                'tfidf': tfidf_similarity
            }
            func = similarity_functions.get(algorithm)
            if not func:
                return jsonify({"error": "Invalid algorithm"}), 400
                
            results = {
                algorithm: round(func(vec1, vec2) * 100, 2)
            }
            
        return jsonify({
            "results": results,
            "text1_length": len(text1),
            "text2_length": len(text2),
            "text1_preview": text1[:100] + '...',
            "text2_preview": text2[:100] + '...'
        })
        
    except Exception as e:
        print("Test error:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/api/analytics/data')
def get_analytics_data():
    try:
        # Add authentication check if required
        if not current_user.is_authenticated:
            return jsonify({'error': 'Unauthorized'}), 401

        # Fetch analytics data from your database
        analytics_data = {
            'analytics': [
                {
                    'title': 'Total Users',
                    'value': get_total_users(),
                    'timestamp': datetime.now().isoformat()
                },
                # Add more analytics metrics as needed
            ]
        }
        
        return jsonify(analytics_data)
    except Exception as e:
        app.logger.error(f"Analytics error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    try:
        scheduler.start()
        print("Scheduler started successfully")
    except Exception as e:
        print(f"Error starting scheduler: {e}")
    
    # Run Flask app with proper configuration
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000,
        threaded=True,
        use_reloader=True
    )

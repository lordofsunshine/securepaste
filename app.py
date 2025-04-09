from quart import Quart, render_template, request, redirect, url_for, flash, session, send_from_directory
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import bcrypt
from cryptography.fernet import Fernet
import uuid
import base64
import asyncio
import string
import random
from collections import defaultdict
from functools import wraps

load_dotenv()

app = Quart(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 60  # Maximum requests per window
RATE_LIMIT_WINDOW = 60  # Window size in seconds
CREATE_LIMIT_REQUESTS = 10  # Maximum paste creation requests
CREATE_LIMIT_WINDOW = 600  # Creation window size in seconds

request_counts = defaultdict(list)
create_counts = defaultdict(list)

SITE_URL = os.getenv('SITE_URL', 'https://securepaste.icu')

def clean_expired_timestamps(ip, timestamps, window):
    """
    Removes expired timestamps for rate limiting
    
    Args:
        ip: Client IP address
        timestamps: List of request timestamps
        window: Time window in seconds
        
    Returns:
        List of timestamps that are still within the time window
    """
    current_time = datetime.utcnow().timestamp()
    return [ts for ts in timestamps if current_time - ts < window]

def is_rate_limited(ip, action='request'):
    """
    Checks if a client has exceeded rate limits
    
    Args:
        ip: Client IP address
        action: Type of action ('request' or 'create')
        
    Returns:
        bool: True if rate limited, False otherwise
    """
    current_time = datetime.utcnow().timestamp()
    
    if action == 'create':
        create_counts[ip] = clean_expired_timestamps(ip, create_counts[ip], CREATE_LIMIT_WINDOW)
        if len(create_counts[ip]) >= CREATE_LIMIT_REQUESTS:
            return True
        create_counts[ip].append(current_time)
    else:
        request_counts[ip] = clean_expired_timestamps(ip, request_counts[ip], RATE_LIMIT_WINDOW)
        if len(request_counts[ip]) >= RATE_LIMIT_REQUESTS:
            return True
        request_counts[ip].append(current_time)
    
    return False

def rate_limit(action='request'):
    """
    Decorator for rate limiting routes
    
    Args:
        action: Type of action to rate limit ('request' or 'create')
        
    Returns:
        Decorated function with rate limiting
    """
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            ip = request.headers.get('X-Real-IP', request.remote_addr)
            
            if is_rate_limited(ip, action):
                return await render_template('error.html',
                    code="429",
                    title="Too Many Requests",
                    message="You've exceeded the rate limit. Please try again later.",
                    button_url="/",
                    button_text="Back to Home"
                ), 429
            
            return await f(*args, **kwargs)
        return decorated_function
    return decorator

# MongoDB connection setup
client = AsyncIOMotorClient(os.getenv('MONGO_URI'))
db = client.securepaste
pastes = db.pastes

# Encryption setup
encryption_key = os.getenv('ENCRYPTION_KEY')
if not encryption_key:
    raise ValueError("ENCRYPTION_KEY not found in environment variables")

padding = len(encryption_key) % 4
if padding:
    encryption_key += '=' * (4 - padding)

fernet = Fernet(encryption_key.encode())

# Characters allowed in paste IDs (removed visually similar characters)
ID_CHARS = string.ascii_letters + string.digits
ID_CHARS = ID_CHARS.replace('l', '').replace('I', '').replace('1', '').replace('O', '').replace('0', '')
MIN_ID_LENGTH = 6

async def generate_unique_id(length):
    """
    Generates a unique ID for a paste
    
    Args:
        length: Length of the ID to generate
        
    Returns:
        str: Unique ID for the paste
    """
    max_attempts = 10
    attempts = 0
    
    while attempts < max_attempts:
        paste_id = ''.join(random.choices(ID_CHARS, k=length))
        if not await pastes.find_one({'_id': paste_id}):
            return paste_id
        attempts += 1
    
    # If we can't generate a unique ID, try with a longer length
    return await generate_unique_id(length + 1)

async def cleanup_expired_pastes():
    """
    Background task to periodically clean up expired pastes
    """
    while True:
        try:
            await pastes.delete_many({'expires_at': {'$lt': datetime.utcnow()}})
            await asyncio.sleep(3600)  # Run once per hour
        except Exception as e:
            print(f"Error during cleanup: {e}")
            await asyncio.sleep(3600)

@app.before_serving
async def startup():
    """
    Application startup hook - creates background task
    """
    app.cleanup_task = asyncio.create_task(cleanup_expired_pastes())

@app.after_serving
async def shutdown():
    """
    Application shutdown hook - cancels background task
    """
    app.cleanup_task.cancel()
    try:
        await app.cleanup_task
    except asyncio.CancelledError:
        pass

def generate_csrf_token():
    """
    Generates a CSRF token and stores it in the session
    
    Returns:
        str: CSRF token
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = str(uuid.uuid4())
    return session['csrf_token']

async def validate_csrf_token():
    """
    Validates the CSRF token in a POST request
    
    Returns:
        bool: True if valid, False otherwise
    """
    if request.method == 'POST':
        form = await request.form
        token = form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            return False
    return True

def csrf_protect(f):
    """
    Decorator to protect routes with CSRF validation
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function with CSRF protection
    """
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not await validate_csrf_token():
            await flash('Invalid CSRF token')
            return redirect(request.url)
        return await f(*args, **kwargs)
    return decorated_function

@app.route('/')
@rate_limit()
async def index():
    """
    Renders the home page
    """
    return await render_template('index.html')

@app.route('/create', methods=['GET', 'POST'])
@rate_limit('create')
@csrf_protect
async def create_paste():
    """
    Handles paste creation
    
    POST parameters:
        title: Paste title (3-12 chars)
        content: Paste content (max 30k chars)
        password: Optional password protection
        expiration: Expiration time ('1h', '1d', '1m', '3m', '6m')
        csrf_token: CSRF protection token
        
    Returns:
        Redirects to the created paste or back to creation form
    """
    if request.method == 'POST':
        form = await request.form
        title = form.get('title', '').strip()
        content = form.get('content', '').strip()
        password = form.get('password')
        expiration = form.get('expiration')
        
        if not content:
            await flash('Content is required')
            return redirect(url_for('create_paste'))
            
        if len(title) < 3 or len(title) > 12:
            await flash('Title must be between 3 and 12 characters')
            return redirect(url_for('create_paste'))
            
        if len(content) > 30000:
            await flash('Content must not exceed 30,000 characters')
            return redirect(url_for('create_paste'))
        
        paste_id = await generate_unique_id(MIN_ID_LENGTH)
        
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else None
        
        expiration_times = {
            '1h': timedelta(hours=1),
            '1d': timedelta(days=1),
            '1m': timedelta(days=30),
            '3m': timedelta(days=90),
            '6m': timedelta(days=180)
        }
        
        expires_at = datetime.utcnow() + expiration_times.get(expiration, timedelta(days=1))
        
        encrypted_content = fernet.encrypt(content.encode())
        
        await pastes.insert_one({
            '_id': paste_id,
            'title': title,
            'content': encrypted_content,
            'password': hashed_password,
            'expires_at': expires_at,
            'created_at': datetime.utcnow(),
            'views': 0
        })
        
        return redirect(url_for('view_paste', paste_id=paste_id))
    
    return await render_template('create.html', csrf_token=generate_csrf_token())

@app.route('/paste/<paste_id>', methods=['GET', 'POST'])
@rate_limit()
@csrf_protect
async def view_paste(paste_id):
    """
    Handles viewing a paste, including password protection
    
    URL parameters:
        paste_id: ID of the paste to view
        
    POST parameters (for password-protected pastes):
        password: Password to access the paste
        csrf_token: CSRF protection token
        
    Returns:
        Rendered paste, password form, or error page
    """
    paste = await pastes.find_one({'_id': paste_id})
    
    if not paste:
        return await render_template('error.html', 
            code="404",
            title="Not Found",
            message="The requested paste doesn't exist or has been deleted.",
            button_url="/",
            button_text="Back to Home"
        ), 404
        
    if paste['expires_at'] < datetime.utcnow():
        await pastes.delete_one({'_id': paste_id})
        return await render_template('error.html',
            code="410",
            title="Expired",
            message="This paste has expired and has been automatically deleted.",
            button_url="/create",
            button_text="Create New Paste"
        ), 410
        
    if paste.get('password'):
        session_key = f'paste_auth_{paste_id}'
        if session.get(session_key) != True:
            if request.method == 'POST':
                form = await request.form
                password = form.get('password')
                
                if not password:
                    await flash('Password is required')
                    return redirect(url_for('view_paste', paste_id=paste_id))
                
                if bcrypt.checkpw(password.encode(), paste['password']):
                    session[session_key] = True
                    await pastes.update_one(
                        {'_id': paste_id},
                        {'$inc': {'views': 1}}
                    )
                    paste = await pastes.find_one({'_id': paste_id})
                    content = fernet.decrypt(paste['content']).decode()
                    return await render_template('view.html', paste=paste, content=content)
                else:
                    await flash('Invalid password')
                    return redirect(url_for('view_paste', paste_id=paste_id))
                    
            return await render_template('password.html', paste=paste, csrf_token=generate_csrf_token())
        
    await pastes.update_one(
        {'_id': paste_id},
        {'$inc': {'views': 1}}
    )
    paste = await pastes.find_one({'_id': paste_id})
    content = fernet.decrypt(paste['content']).decode()
    return await render_template('view.html', paste=paste, content=content)

@app.route('/raw/<paste_id>')
@rate_limit()
async def raw_paste(paste_id):
    """
    Returns the raw content of a paste
    
    URL parameters:
        paste_id: ID of the paste to view
        
    Returns:
        Raw paste content as plain text or error page
    """
    paste = await pastes.find_one({'_id': paste_id})
    
    if not paste:
        return await render_template('error.html', 
            code="404",
            title="Not Found",
            message="The requested paste doesn't exist or has been deleted.",
            button_url="/",
            button_text="Back to Home"
        ), 404
        
    if paste['expires_at'] < datetime.utcnow():
        await pastes.delete_one({'_id': paste_id})
        return await render_template('error.html',
            code="410",
            title="Expired",
            message="This paste has expired and has been automatically deleted.",
            button_url="/create",
            button_text="Create New Paste"
        ), 410
        
    if paste.get('password'):
        session_key = f'paste_auth_{paste_id}'
        if session.get(session_key) != True:
            return await render_template('password.html', paste=paste)
    
    content = fernet.decrypt(paste['content']).decode()
    return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/robots.txt')
async def robots():
    """
    Serves robots.txt file
    """
    return await send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
async def sitemap():
    """
    Dynamically generates sitemap.xml
    
    Returns:
        XML content for the sitemap
    """
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url>
            <loc>{}/</loc>
            <changefreq>weekly</changefreq>
            <priority>1.0</priority>
            <lastmod>{}</lastmod>
        </url>
        <url>
            <loc>{}/create</loc>
            <changefreq>weekly</changefreq>
            <priority>0.8</priority>
            <lastmod>{}</lastmod>
        </url>
    </urlset>""".format(
        SITE_URL,
        datetime.utcnow().strftime('%Y-%m-%d'),
        SITE_URL,
        datetime.utcnow().strftime('%Y-%m-%d')
    )
    
    return xml_content, 200, {'Content-Type': 'application/xml'}

@app.errorhandler(404)
async def not_found_error(error):
    """
    Handles 404 Not Found errors
    """
    return await render_template('error.html',
        code="404",
        title="Not Found",
        message="The requested page doesn't exist.",
        button_url="/",
        button_text="Back to Home"
    ), 404

@app.errorhandler(500)
async def internal_error(error):
    """
    Handles 500 Internal Server errors
    """
    return await render_template('error.html',
        code="500",
        title="Server Error",
        message="Something went wrong on our end. Please try again later.",
        button_url="/",
        button_text="Back to Home"
    ), 500

if __name__ == '__main__':
    app.run(debug=True) 
from flask import Flask, render_template, request, jsonify, abort, Response, redirect, url_for, session
import os, json, time, re, secrets, logging
from urllib.parse import quote, unquote
from datetime import datetime, timedelta
from collections import defaultdict
import bcrypt
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder='../templates')

# ─── Konfigurasi Keamanan ─────────────────────────────
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    _secret = secrets.token_hex(32)
    print("⚠️  WARNING: SECRET_KEY tidak di-set. Session akan reset setiap restart!")
app.secret_key = _secret

app.config.update(
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SAMESITE  = 'Lax',
    SESSION_COOKIE_SECURE    = os.environ.get('HTTPS', 'false') == 'true',
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
)

# Untuk Vercel, gunakan filesystem sementara
import tempfile
PASTES_DIR = os.path.join(tempfile.gettempdir(), 'pastes')
os.makedirs(PASTES_DIR, exist_ok=True)

USERS_FILE = os.path.join(tempfile.gettempdir(), 'users.json')

# Logging configuration
logging.basicConfig(
    filename='/tmp/security.log',
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)
security_log = logging.getLogger('security')

# ─── Brute Force Protection ───────────────────────────
_login_attempts = defaultdict(lambda: {'count': 0, 'locked_until': 0, 'last_attempt': 0})

MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 300
ATTEMPT_WINDOW  = 600

def get_client_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr

def check_rate_limit(ip):
    rec = _login_attempts[ip]
    now = time.time()
    if now - rec['last_attempt'] > ATTEMPT_WINDOW:
        rec['count'] = 0
        rec['locked_until'] = 0
    if rec['locked_until'] > now:
        remaining = int(rec['locked_until'] - now)
        return False, remaining
    return True, 0

def record_failed_attempt(ip, username):
    rec = _login_attempts[ip]
    rec['count'] += 1
    rec['last_attempt'] = time.time()
    if rec['count'] >= MAX_ATTEMPTS:
        rec['locked_until'] = time.time() + LOCKOUT_SECONDS
        security_log.warning(f"LOCKOUT ip={ip} user={username} attempts={rec['count']}")
    else:
        security_log.warning(f"FAILED_LOGIN ip={ip} user={username} attempts={rec['count']}")

def record_success(ip):
    _login_attempts[ip] = {'count': 0, 'locked_until': 0, 'last_attempt': 0}

# ─── User Management ──────────────────────────────────
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    default_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt(12)).decode()
    return {"admin": default_hash}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

if not os.path.exists(USERS_FILE):
    save_users(load_users())

# ─── Helpers ──────────────────────────────────────────
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12)).decode() if pw else None

def verify_pw(pw, stored):
    if not pw or not stored:
        return False
    try:
        return bcrypt.checkpw(pw.encode(), stored.encode())
    except Exception:
        return False

def title_to_id(title):
    safe = re.sub(r'[/\\<>:"|?*\x00-\x1f]', '_', title.strip())
    return safe.strip('. ') or 'untitled'

def load_paste(pid):
    pid = unquote(pid)
    pid = re.sub(r'[/\\<>:"|?*\x00-\x1f]', '_', pid).strip('. ')
    path = os.path.join(PASTES_DIR, pid + '.json')
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_paste(data):
    path = os.path.join(PASTES_DIR, data['id'] + '.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def public_meta(p):
    return {
        'id': p['id'],
        'title': p.get('title', 'Untitled'),
        'created': p.get('created', 0),
        'lines': p.get('content', '').count('\n') + 1,
        'size': len(p.get('content', '').encode()),
        'locked': bool(p.get('password_hash'))
    }

def all_pastes():
    result = []
    for fname in os.listdir(PASTES_DIR):
        if fname.endswith('.json'):
            with open(os.path.join(PASTES_DIR, fname), 'r', encoding='utf-8') as f:
                try:
                    result.append(json.load(f))
                except:
                    pass
    result.sort(key=lambda x: x.get('created', 0), reverse=True)
    return result

def is_browser_request():
    ua = request.headers.get('User-Agent', '').lower()
    accept = request.headers.get('Accept', '').lower()
    is_browser = 'text/html' in accept
    is_roblox = 'roblox' in ua
    return is_browser and not is_roblox

ALLOWED_USER_AGENTS = ['roblox', 'httpget', 'python-requests', 'curl', 'wget', 'okhttp']

def is_allowed_user_agent():
    ua = request.headers.get('User-Agent', '').lower()
    if not ua:
        return False
    return any(allowed in ua for allowed in ALLOWED_USER_AGENTS)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login_page', next=request.url))
        return f(*args, **kwargs)
    return decorated

# ─── Auth Routes ──────────────────────────────────────
@app.route('/login')
def login_page():
    if session.get('logged_in'):
        return redirect('/')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    ip = get_client_ip()

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        security_log.warning(f"BLOCKED_LOGIN ip={ip} remaining={remaining}s")
        return jsonify({
            'error': f'Terlalu banyak percobaan. Coba lagi dalam {remaining} detik.',
            'locked': True,
            'retry_after': remaining
        }), 429

    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username dan password diperlukan'}), 400

    if len(username) > 64 or len(password) > 256:
        return jsonify({'error': 'Input tidak valid'}), 400

    users = load_users()
    stored_hash = users.get(username)

    dummy = "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    valid = verify_pw(password, stored_hash if stored_hash else dummy)

    if not stored_hash or not valid:
        record_failed_attempt(ip, username)
        rec = _login_attempts[ip]
        remaining_attempts = max(0, MAX_ATTEMPTS - rec['count'])

        msg = 'Username atau password salah.'
        if remaining_attempts <= 2 and remaining_attempts > 0:
            msg += f' Sisa {remaining_attempts} percobaan sebelum dikunci.'
        elif remaining_attempts == 0:
            msg = f'Akun dikunci selama {LOCKOUT_SECONDS // 60} menit akibat terlalu banyak percobaan.'

        return jsonify({'error': msg}), 401

    record_success(ip)
    security_log.warning(f"LOGIN_SUCCESS ip={ip} user={username}")

    session.clear()
    session.permanent = True
    session['logged_in'] = True
    session['username'] = username
    session['login_time'] = time.time()

    csrf_token = secrets.token_hex(24)
    session['csrf_token'] = csrf_token

    return jsonify({
        'success': True,
        'username': username,
        'csrf_token': csrf_token
    })

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/me', methods=['GET'])
def api_me():
    if session.get('logged_in'):
        return jsonify({
            'logged_in': True,
            'username': session.get('username')
        })
    return jsonify({'logged_in': False}), 401

# ─── Page Routes ──────────────────────────────────────
@app.route('/')
@login_required
def index():
    return render_template('website.html')

@app.route('/<path:pid>')
def view_or_raw(pid):
    if pid.startswith('api/') or pid in ('login', 'logout'):
        abort(404)

    if pid.endswith('/raw'):
        if is_browser_request():
            return render_template('error.html'), 403
        if not is_allowed_user_agent():
            security_log.warning(
                f"UA_BLOCKED pid={pid[:-4]} ip={get_client_ip()} "
                f"ua={request.headers.get('User-Agent', 'none')}"
            )
            return render_template('error.html'), 403
        p = load_paste(pid[:-4])
        if not p:
            abort(404)
        if p.get('password_hash'):
            pw = request.args.get('password', '')
            if not verify_pw(pw, p['password_hash']):
                security_log.warning(f"RAW_UNAUTHORIZED pid={pid[:-4]} ip={get_client_ip()}")
                return Response('403 Forbidden: Password required', status=403, mimetype='text/plain')
        resp = Response(p['content'], mimetype='text/plain; charset=utf-8')
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Cache-Control'] = 'no-cache'
        return resp

    if not session.get('logged_in'):
        return redirect(url_for('login_page', next=request.url))
    p = load_paste(pid)
    if not p:
        abort(404)
    return render_template('website.html')

# ─── API (semua butuh login) ───────────────────────────
@app.route('/api/pastes', methods=['GET'])
@login_required
def api_list():
    return jsonify([public_meta(p) for p in all_pastes()])

@app.route('/api/pastes', methods=['POST'])
@login_required
def api_create():
    data = request.get_json()
    content  = data.get('content', '').strip()
    title    = data.get('title', '').strip() or 'Untitled'
    password = data.get('password', '').strip()
    if not content:
        return jsonify({'error': 'Konten tidak boleh kosong'}), 400
    pid = title_to_id(title)
    base, counter = pid, 2
    while os.path.exists(os.path.join(PASTES_DIR, pid + '.json')):
        pid = f"{base}_{counter}"; counter += 1
    paste = {
        'id': pid, 'title': title, 'content': content,
        'created': time.time(),
        'password_hash': hash_pw(password) if password else None,
        'created_by': session.get('username', 'unknown')
    }
    save_paste(paste)
    encoded = quote(pid, safe='')
    return jsonify({'id': pid, 'url': f'/{encoded}', 'raw_url': f'/{encoded}/raw'}), 201

@app.route('/api/pastes/<path:pid>', methods=['GET'])
@login_required
def api_get(pid):
    p = load_paste(pid)
    if not p:
        return jsonify({'error': 'Paste tidak ditemukan'}), 404
    if p.get('password_hash'):
        pw = request.args.get('password', '')
        if not verify_pw(pw, p['password_hash']):
            return jsonify({'locked': True, 'id': p['id'], 'title': p.get('title'), 'error': 'Password diperlukan'}), 403
    return jsonify({
        'id': p['id'], 'title': p.get('title'), 'content': p.get('content', ''),
        'created': p.get('created', 0), 'locked': bool(p.get('password_hash')),
        'created_by': p.get('created_by', '')
    })

@app.route('/api/pastes/<path:pid>', methods=['PUT'])
@login_required
def api_update(pid):
    p = load_paste(pid)
    if not p:
        return jsonify({'error': 'Paste tidak ditemukan'}), 404
    data = request.get_json()
    if 'content'  in data: p['content'] = data['content']
    if 'title'    in data: p['title']   = data['title'] or 'Untitled'
    if 'password' in data:
        pw = data['password'].strip()
        p['password_hash'] = hash_pw(pw) if pw else None
    p['updated'] = time.time()
    save_paste(p)
    return jsonify({'success': True})

@app.route('/api/pastes/<path:pid>', methods=['DELETE'])
@login_required
def api_delete(pid):
    p = load_paste(pid)
    if not p:
        return jsonify({'error': 'Paste tidak ditemukan'}), 404
    path = os.path.join(PASTES_DIR, re.sub(r'[/\\<>:"|?*\x00-\x1f]', '_', unquote(pid)).strip('. ') + '.json')
    if os.path.exists(path):
        os.remove(path)
    return jsonify({'success': True})

# ─── Error Handlers ───────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('error.html'), 404

@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('error.html'), 403

@app.errorhandler(500)
def internal_error(e):
    security_log.error(f"Internal server error: {str(e)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('error.html'), 500

# Handler untuk Vercel
def handler(request, context):
    return app(request, context)

# Untuk development lokal
if __name__ == '__main__':
    print("🚀 Server starting...")
    app.run(debug=True, host='0.0.0.0', port=5000)

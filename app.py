import sqlite3, os, json, hashlib, secrets, uuid
from decimal import Decimal
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, g, request, jsonify, send_from_directory

app = Flask(__name__, static_url_path='')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
DB_PATH = os.path.join(os.path.dirname(__file__), 'store.db')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            image TEXT NOT NULL DEFAULT '',
            badge TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS product_sizes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            price INTEGER NOT NULL,
            original_price INTEGER,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            customer_id INTEGER,
            customer_name TEXT NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            phone TEXT NOT NULL DEFAULT '',
            address TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',
            pin TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT '',
            payment_method TEXT NOT NULL DEFAULT 'card',
            status TEXT NOT NULL DEFAULT 'confirmed',
            total INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        );
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT NOT NULL,
            product_id INTEGER,
            product_name TEXT NOT NULL,
            product_image TEXT NOT NULL DEFAULT '',
            size TEXT NOT NULL DEFAULT '',
            quantity INTEGER NOT NULL DEFAULT 1,
            price INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
    """)
    db.commit()
    try:
        db.execute("ALTER TABLE orders ADD COLUMN customer_id INTEGER REFERENCES customers(id)")
        db.commit()
    except sqlite3.OperationalError:
        pass

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Admin-Token') or request.args.get('token')
        if not token or token != ADMIN_PASSWORD_HASH:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ── Products ─────────────────────────────────────────────────

@app.route('/api/products', methods=['GET'])
def get_products():
    db = get_db()
    cur = db.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = [dict(r) for r in cur.fetchall()]
    for p in products:
        sz = db.execute("SELECT * FROM product_sizes WHERE product_id=?", (p['id'],))
        p['sizes'] = [dict(s) for s in sz.fetchall()]
    return jsonify(products)

@app.route('/api/products/<int:pid>', methods=['GET'])
def get_product(pid):
    db = get_db()
    p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p: return jsonify({'error': 'Not found'}), 404
    p = dict(p)
    sz = db.execute("SELECT * FROM product_sizes WHERE product_id=?", (pid,))
    p['sizes'] = [dict(s) for s in sz.fetchall()]
    return jsonify(p)

@app.route('/api/products', methods=['POST'])
@require_admin
def add_product():
    data = request.get_json()
    db = get_db()
    cur = db.execute(
        "INSERT INTO products (name, category, description, image, badge) VALUES (?,?,?,?,?)",
        (data['name'], data.get('category', ''), data.get('description', ''),
         data.get('image', ''), data.get('badge', ''))
    )
    pid = cur.lastrowid
    for s in data.get('sizes', []):
        db.execute(
            "INSERT INTO product_sizes (product_id, label, price, original_price) VALUES (?,?,?,?)",
            (pid, s['label'], int(s['price']), int(s['originalPrice']) if s.get('originalPrice') else None)
        )
    db.commit()
    return jsonify({'id': pid, 'ok': True}), 201

@app.route('/api/products/<int:pid>', methods=['DELETE'])
@require_admin
def delete_product(pid):
    db = get_db()
    db.execute("DELETE FROM products WHERE id=?", (pid,))
    db.commit()
    return jsonify({'ok': True})

# ── Orders ───────────────────────────────────────────────────

@app.route('/api/orders', methods=['GET'])
def get_orders():
    db = get_db()
    token = request.headers.get('X-Admin-Token')
    email = request.args.get('email', '')
    if token == ADMIN_PASSWORD_HASH:
        rows = db.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    elif email:
        rows = db.execute("SELECT * FROM orders WHERE email=? ORDER BY created_at DESC", (email,)).fetchall()
    else:
        return jsonify({'error': 'Not authorized'}), 401
    orders = []
    for r in rows:
        o = dict(r)
        items = db.execute("SELECT * FROM order_items WHERE order_id=?", (o['id'],)).fetchall()
        o['items'] = [dict(i) for i in items]
        orders.append(o)
    return jsonify(orders)

@app.route('/api/orders', methods=['POST'])
def create_order():
    data = request.get_json()
    db = get_db()
    oid = 'PST-' + str(int(datetime.now().timestamp() * 1000))[-6:]
    db.execute(
        """INSERT INTO orders (id, customer_id, customer_name, email, phone, address, city, pin, state, payment_method, status, total)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (oid, data.get('customerId'), data['name'], data.get('email', ''), data.get('phone', ''),
         data.get('address', ''), data.get('city', ''), data.get('pin', ''),
         data.get('state', ''), data.get('paymentMethod', 'card'), 'confirmed', int(data['total']))
    )
    for item in data.get('items', []):
        db.execute(
            "INSERT INTO order_items (order_id, product_id, product_name, product_image, size, quantity, price) VALUES (?,?,?,?,?,?,?)",
            (oid, item.get('productId'), item['name'], item.get('image', ''),
             item.get('size', ''), int(item.get('qty', 1)), int(item['price']))
        )
    db.commit()
    return jsonify({'id': oid, 'ok': True}), 201

@app.route('/api/orders/<order_id>', methods=['PATCH'])
@require_admin
def update_order(order_id):
    data = request.get_json()
    db = get_db()
    db.execute("UPDATE orders SET status=? WHERE id=?", (data['status'], order_id))
    db.commit()
    return jsonify({'ok': True})

# ── Dashboard ────────────────────────────────────────────────

@app.route('/api/dashboard', methods=['GET'])
@require_admin
def dashboard():
    db = get_db()
    orders = [dict(r) for r in db.execute("SELECT * FROM orders").fetchall()]
    revenue = sum(o['total'] for o in orders if o['status'] != 'cancelled')
    customers = set(o['email'] for o in orders if o['email'])
    pending = sum(1 for o in orders if o['status'] in ('confirmed', 'processing'))
    recent = sorted(orders, key=lambda x: x['created_at'], reverse=True)[:10]
    for o in recent:
        items = db.execute("SELECT * FROM order_items WHERE order_id=?", (o['id'],)).fetchall()
        o['items'] = [dict(i) for i in items]
    return jsonify({
        'revenue': revenue, 'totalOrders': len(orders),
        'customers': len(customers), 'pending': pending,
        'recentOrders': recent
    })

# ── Auth ─────────────────────────────────────────────────────

@app.route('/api/auth/admin', methods=['POST'])
def admin_login():
    data = request.get_json()
    if hashlib.sha256(data.get('password', '').encode()).hexdigest() == ADMIN_PASSWORD_HASH:
        return jsonify({'token': ADMIN_PASSWORD_HASH})
    return jsonify({'error': 'Wrong password'}), 401

@app.route('/api/auth/signup', methods=['POST'])
def customer_signup():
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()
    password = data.get('password', '')
    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password required'}), 400
    db = get_db()
    exists = db.execute("SELECT id FROM customers WHERE email=?", (email,)).fetchone()
    if exists:
        return jsonify({'error': 'Email already registered'}), 409
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    cur = db.execute(
        "INSERT INTO customers (name, email, phone, password_hash) VALUES (?,?,?,?)",
        (name, email, phone, pw_hash)
    )
    db.commit()
    return jsonify({'id': cur.lastrowid, 'name': name, 'email': email}), 201

@app.route('/api/auth/login', methods=['POST'])
def customer_login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    db = get_db()
    row = db.execute("SELECT * FROM customers WHERE email=?", (email,)).fetchone()
    if not row:
        return jsonify({'error': 'No account found. Please sign up.'}), 401
    if hashlib.sha256(password.encode()).hexdigest() != row['password_hash']:
        return jsonify({'error': 'Wrong password'}), 401
    return jsonify({'id': row['id'], 'name': row['name'], 'email': row['email'], 'phone': row['phone']})

# ── Image upload ──────────────────────────────────────────

ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/api/upload', methods=['POST'])
@require_admin
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ALLOWED_EXT:
        return jsonify({'error': 'Invalid type. Allowed: png, jpg, jpeg, gif, webp'}), 400
    name = str(uuid.uuid4()) + '.' + ext
    path = os.path.join(UPLOAD_DIR, name)
    f.save(path)
    return jsonify({'url': '/uploads/' + name})

# ── Serve frontend ──────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

# ── Seed ────────────────────────────────────────────────────

SEED_DATA = [
    {'name': '22pc Automotive Wall Combo', 'category': 'Wall Setup', 'description': 'Complete car-themed wall transformation. 22 premium glossy prints.', 'image': 'https://picsum.photos/seed/auto1/600/600', 'badge': 'sale', 'sizes': [{'label': 'A4', 'price': 499, 'originalPrice': 999}, {'label': 'A3', 'price': 699, 'originalPrice': 1299}, {'label': '12x18', 'price': 899, 'originalPrice': 1599}]},
    {'name': 'Ultimate Fan Wall Setup — 24 A4 Pack', 'category': 'Wall Setup', 'description': '24-piece cinematic wall combo. A4 museum-quality prints.', 'image': 'https://picsum.photos/seed/cinema1/600/600', 'badge': 'sale', 'sizes': [{'label': 'A4', 'price': 549, 'originalPrice': 1099}, {'label': 'A3', 'price': 749, 'originalPrice': 1499}, {'label': '12x18', 'price': 949, 'originalPrice': 1799}]},
    {'name': 'JDM Legends Sticker Pack — 50 Pcs', 'category': 'Sticker Pack', 'description': '50 waterproof vinyl JDM car stickers. Die-cut premium.', 'image': 'https://picsum.photos/seed/jdm1/600/600', 'badge': 'trending', 'sizes': [{'label': 'A4', 'price': 199, 'originalPrice': 399}, {'label': 'A3', 'price': 299, 'originalPrice': 599}, {'label': '12x18', 'price': 399, 'originalPrice': 799}]},
    {'name': 'Minimal Car Blueprint Poster Set', 'category': 'Poster', 'description': '3 detailed blueprint posters. A3, 200gsm matte.', 'image': 'https://picsum.photos/seed/blueprint1/600/600', 'badge': 'sale', 'sizes': [{'label': 'A4', 'price': 349, 'originalPrice': 699}, {'label': 'A3', 'price': 499, 'originalPrice': 999}, {'label': '12x18', 'price': 649, 'originalPrice': 1299}]},
    {'name': 'Anime Action Sticker Combo — 40 Pcs', 'category': 'Anime', 'description': '40 premium anime stickers. Waterproof, UV-resistant.', 'image': 'https://picsum.photos/seed/anime1/600/600', 'badge': 'new', 'sizes': [{'label': 'A4', 'price': 179, 'originalPrice': 349}, {'label': 'A3', 'price': 279, 'originalPrice': 549}, {'label': '12x18', 'price': 379, 'originalPrice': 749}]},
    {'name': 'Supercar Sticker Bomb — 60 Pcs', 'category': 'Sticker Pack', 'description': '60 supercar stickers. Premium waterproof vinyl.', 'image': 'https://picsum.photos/seed/supercar1/600/600', 'badge': 'pack', 'sizes': [{'label': 'A4', 'price': 249, 'originalPrice': 499}, {'label': 'A3', 'price': 349, 'originalPrice': 699}, {'label': '12x18', 'price': 449, 'originalPrice': 899}]},
    {'name': 'Vintage Racing Poster Set', 'category': 'Automotive', 'description': '4 vintage racing posters. Le Mans & F1 era. A3.', 'image': 'https://picsum.photos/seed/vintage1/600/600', 'badge': 'sale', 'sizes': [{'label': 'A4', 'price': 379, 'originalPrice': 749}, {'label': 'A3', 'price': 529, 'originalPrice': 1049}, {'label': '12x18', 'price': 679, 'originalPrice': 1349}]},
    {'name': 'Dark Cinematic Poster Collection', 'category': 'Cinematic', 'description': '5 dark movie posters. A2 deep black matte.', 'image': 'https://picsum.photos/seed/dark1/600/600', 'badge': 'sale', 'sizes': [{'label': 'A4', 'price': 399, 'originalPrice': 799}, {'label': 'A3', 'price': 599, 'originalPrice': 1199}, {'label': '12x18', 'price': 799, 'originalPrice': 1599}]},
    {'name': 'Automotive Wall Collage Kit — 15 Pcs', 'category': 'Wall Setup', 'description': '15 mixed-size auto posters. A5 to A3 gallery wall.', 'image': 'https://picsum.photos/seed/collage1/600/600', 'badge': 'trending', 'sizes': [{'label': 'A4', 'price': 449, 'originalPrice': 899}, {'label': 'A3', 'price': 649, 'originalPrice': 1299}, {'label': '12x18', 'price': 849, 'originalPrice': 1699}]},
]

def run_seed():
    db = get_db()
    existing = db.execute("SELECT COUNT(*) as c FROM products").fetchone()['c']
    if existing > 0:
        return False
    for p in SEED_DATA:
        cur = db.execute(
            "INSERT INTO products (name, category, description, image, badge) VALUES (?,?,?,?,?)",
            (p['name'], p['category'], p.get('description', ''), p['image'], p.get('badge', ''))
        )
        pid = cur.lastrowid
        for s in p['sizes']:
            db.execute(
                "INSERT INTO product_sizes (product_id, label, price, original_price) VALUES (?,?,?,?)",
                (pid, s['label'], s['price'], s.get('originalPrice'))
            )
    db.commit()
    return True

@app.route('/api/seed', methods=['POST'])
@require_admin
def seed():
    return jsonify({'ok': True, 'count': len(SEED_DATA), 'seeded': run_seed()})

with app.app_context():
    init_db()
    if run_seed():
        print("[auto-seed] Default products seeded")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

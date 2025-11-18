from flask import Flask, request, redirect, url_for, session, flash, jsonify, render_template_string
import sqlite3
import hashlib
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'tilapia_suite_secret_key_2025'

DATABASE = 'tilapia_suite.db'

# ==================== HTML TEMPLATES ====================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Tilapia Suite{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
    <style>
        :root {
            --primary-color: #1E88E5;
            --secondary-color: #424242;
            --success-color: #43A047;
            --danger-color: #E53935;
            --warning-color: #FB8C00;
            --info-color: #00ACC1;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
        }
        .navbar-brand {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary-color) !important;
        }
        .sidebar {
            min-height: calc(100vh - 56px);
            background-color: #fff;
            border-right: 1px solid #dee2e6;
            padding: 20px;
        }
        .sidebar .nav-link {
            color: #333;
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background-color: var(--primary-color);
            color: white;
        }
        .main-content {
            padding: 30px;
        }
        .card {
            border: none;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .card-header {
            background-color: var(--primary-color);
            color: white;
            border-radius: 10px 10px 0 0 !important;
            padding: 15px 20px;
            font-weight: 600;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .metric-card.success {
            background: linear-gradient(135deg, #43A047 0%, #1B5E20 100%);
        }
        .metric-card.danger {
            background: linear-gradient(135deg, #E53935 0%, #B71C1C 100%);
        }
        .metric-card.warning {
            background: linear-gradient(135deg, #FB8C00 0%, #E65100 100%);
        }
        .metric-card.info {
            background: linear-gradient(135deg, #00ACC1 0%, #006064 100%);
        }
        .metric-card h3 {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }
        .metric-card p {
            margin: 0;
            opacity: 0.9;
        }
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        .btn-primary:hover {
            background-color: #1565C0;
            border-color: #1565C0;
        }
        .table {
            background-color: white;
        }
        .table thead th {
            background-color: #f8f9fa;
            border-bottom: 2px solid var(--primary-color);
        }
        .alert {
            border-radius: 10px;
            border: none;
        }
        .footer {
            background-color: #fff;
            padding: 20px;
            text-align: center;
            border-top: 1px solid #dee2e6;
            margin-top: 50px;
        }
    </style>
    {% block extra_css %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-fish"></i> Tilapia Suite
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    {% if session.user_id %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle"></i> {{ session.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="/settings">
                                <i class="bi bi-gear"></i> Pengaturan
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="/logout">
                                <i class="bi bi-box-arrow-right"></i> Logout
                            </a></li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="/login">
                            <i class="bi bi-box-arrow-in-right"></i> Login
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/register">
                            <i class="bi bi-person-plus"></i> Register
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <div class="container mt-3">
                {% for category, message in messages %}
                <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}
    
    <div class="container-fluid">
        <div class="row">
            {% if session.user_id %}
            <div class="col-md-2 sidebar">
                <div class="mb-4">
                    <h6 class="text-muted">{{ session.role|upper }}</h6>
                    <p class="mb-0">{{ session.username }}</p>
                </div>
                {% block sidebar %}{% endblock %}
            </div>
            <div class="col-md-10 main-content">
                {% block content %}{% endblock %}
            </div>
            {% else %}
            <div class="col-12">
                {% block full_content %}{% endblock %}
            </div>
            {% endif %}
        </div>
    </div>
    
    <footer class="footer">
        <p class="mb-0">&copy; 2025 Tilapia Suite - Sistem Akuntansi Budidaya Ikan Mujair</p>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    {% block extra_js %}{% endblock %}
</body>
</html>
"""

INDEX_TEMPLATE = BASE_TEMPLATE.replace("{% block full_content %}{% endblock %}", """
{% block full_content %}
<div class="container">
    <div class="text-center py-5">
        <h1 class="display-3 fw-bold text-primary mb-3">
            <i class="bi bi-fish"></i> Tilapia Suite
        </h1>
        <p class="lead text-muted mb-5">Sistem Akuntansi Budidaya Ikan Mujair</p>
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-body p-5">
                        <h3 class="mb-4">Selamat Datang</h3>
                        <p class="mb-4">Sistem terintegrasi untuk mengelola akuntansi budidaya ikan mujair Anda</p>
                        <div class="row g-3">
                            <div class="col-md-3">
                                <div class="card text-center h-100">
                                    <div class="card-body">
                                        <i class="bi bi-cash-coin display-4 text-primary mb-3"></i>
                                        <h5>Kasir</h5>
                                        <p class="small text-muted">Transaksi penjualan</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card text-center h-100">
                                    <div class="card-body">
                                        <i class="bi bi-graph-up display-4 text-success mb-3"></i>
                                        <h5>Akuntan</h5>
                                        <p class="small text-muted">Laporan keuangan</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card text-center h-100">
                                    <div class="card-body">
                                        <i class="bi bi-briefcase display-4 text-warning mb-3"></i>
                                        <h5>Owner</h5>
                                        <p class="small text-muted">Dashboard bisnis</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card text-center h-100">
                                    <div class="card-body">
                                        <i class="bi bi-tools display-4 text-info mb-3"></i>
                                        <h5>Karyawan</h5>
                                        <p class="small text-muted">Pembelian & stok</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="mt-5">
                            <a href="/login" class="btn btn-primary btn-lg me-2">
                                <i class="bi bi-box-arrow-in-right"></i> Login
                            </a>
                            <a href="/register" class="btn btn-outline-primary btn-lg">
                                <i class="bi bi-person-plus"></i> Register
                            </a>
                        </div>
                        <div class="mt-4">
                            <p class="small text-muted mb-0">Demo Accounts:</p>
                            <p class="small">
                                <strong>Kasir:</strong> demo_kasir / Demo123! |
                                <strong>Akuntan:</strong> demo_akuntan / Demo123! |
                                <strong>Owner:</strong> demo_owner / Demo123! |
                                <strong>Karyawan:</strong> demo_karyawan / Demo123!
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
""")

LOGIN_TEMPLATE = BASE_TEMPLATE.replace("{% block full_content %}{% endblock %}", """
{% block full_content %}
<div class="container">
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-5">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0"><i class="bi bi-box-arrow-in-right"></i> Login</h4>
                </div>
                <div class="card-body p-4">
                    <form method="POST" action="/login">
                        <div class="mb-3">
                            <label class="form-label">Role</label>
                            <select name="role" class="form-select" required>
                                <option value="kasir">💤 Kasir</option>
                                <option value="akuntan">📊 Akuntan</option>
                                <option value="owner">💼 Owner</option>
                                <option value="karyawan">🔧 Karyawan</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Username</label>
                            <input type="text" name="username" class="form-control" required placeholder="Masukkan username">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" required placeholder="Masukkan password">
                        </div>
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-box-arrow-in-right"></i> Login
                        </button>
                    </form>
                    <div class="text-center mt-3">
                        <p class="mb-0">Belum punya akun? <a href="/register">Daftar disini</a></p>
                    </div>
                    <hr>
                    <div class="alert alert-info mb-0">
                        <small>
                            <strong>Demo Accounts:</strong><br>
                            Kasir: demo_kasir / Demo123!<br>
                            Akuntan: demo_akuntan / Demo123!<br>
                            Owner: demo_owner / Demo123!<br>
                            Karyawan: demo_karyawan / Demo123!
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
""")

REGISTER_TEMPLATE = BASE_TEMPLATE.replace("{% block full_content %}{% endblock %}", """
{% block full_content %}
<div class="container">
    <div class="row justify-content-center align-items-center" style="min-height: 80vh;">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0"><i class="bi bi-person-plus"></i> Register</h4>
                </div>
                <div class="card-body p-4">
                    <form method="POST" action="/register">
                        <div class="mb-3">
                            <label class="form-label">Role</label>
                            <select name="role" class="form-select" required>
                                <option value="kasir">💤 Kasir</option>
                                <option value="akuntan">📊 Akuntan</option>
                                <option value="owner">💼 Owner</option>
                                <option value="karyawan">🔧 Karyawan</option>
                            </select>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Username *</label>
                                <input type="text" name="username" class="form-control" required minlength="4" placeholder="Min. 4 karakter">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Nama Lengkap</label>
                                <input type="text" name="nama_lengkap" class="form-control" placeholder="Opsional">
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">No. Telepon</label>
                            <input type="tel" name="no_telepon" class="form-control" placeholder="Opsional">
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Password *</label>
                                <input type="password" name="password" class="form-control" required minlength="6" placeholder="Min. 6 karakter">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Konfirmasi Password *</label>
                                <input type="password" name="confirm_password" class="form-control" required placeholder="Ulangi password">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-person-plus"></i> Daftar
                        </button>
                    </form>
                    <div class="text-center mt-3">
                        <p class="mb-0">Sudah punya akun? <a href="/login">Login disini</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
""")

# ==================== HELPER FUNCTIONS ====================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DATABASE, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Tabel users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        nama_lengkap TEXT,
        no_telepon TEXT,
        alamat TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Tabel transaksi penjualan
    c.execute('''CREATE TABLE IF NOT EXISTS transaksi_penjualan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        no_struk TEXT UNIQUE NOT NULL,
        tanggal DATE NOT NULL,
        waktu TIME NOT NULL,
        jumlah_kg REAL NOT NULL,
        harga_per_kg REAL NOT NULL,
        total REAL NOT NULL,
        metode_bayar TEXT NOT NULL,
        kasir_id INTEGER,
        status TEXT DEFAULT 'selesai',
        FOREIGN KEY (kasir_id) REFERENCES users(id)
    )''')
    
    # Tabel chart of accounts
    c.execute('''CREATE TABLE IF NOT EXISTS chart_of_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kode_akun TEXT UNIQUE NOT NULL,
        nama_akun TEXT NOT NULL,
        kategori TEXT NOT NULL,
        saldo_normal TEXT NOT NULL
    )''')
    
    # Tabel jurnal umum
    c.execute('''CREATE TABLE IF NOT EXISTS jurnal_umum (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tanggal DATE NOT NULL,
        kode_akun TEXT NOT NULL,
        keterangan TEXT,
        debit REAL DEFAULT 0,
        kredit REAL DEFAULT 0,
        ref TEXT,
        FOREIGN KEY (kode_akun) REFERENCES chart_of_accounts(kode_akun)
    )''')
    
    # Tabel jurnal penjualan
    c.execute('''CREATE TABLE IF NOT EXISTS jurnal_penjualan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tanggal DATE NOT NULL,
        no_faktur TEXT,
        keterangan TEXT,
        debit_kas REAL DEFAULT 0,
        kredit_penjualan REAL DEFAULT 0,
        debit_hpp REAL DEFAULT 0,
        kredit_persediaan REAL DEFAULT 0
    )''')
    
    # Tabel persediaan
    c.execute('''CREATE TABLE IF NOT EXISTS persediaan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tanggal DATE NOT NULL,
        jenis_transaksi TEXT NOT NULL,
        jumlah REAL NOT NULL,
        harga_satuan REAL NOT NULL,
        total REAL NOT NULL,
        saldo_jumlah REAL NOT NULL,
        saldo_nilai REAL NOT NULL
    )''')
    
    # Tabel biaya
    c.execute('''CREATE TABLE IF NOT EXISTS biaya (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tanggal DATE NOT NULL,
        kategori_biaya TEXT NOT NULL,
        keterangan TEXT,
        nominal REAL NOT NULL,
        kode_akun TEXT,
        FOREIGN KEY (kode_akun) REFERENCES chart_of_accounts(kode_akun)
    )''')
    
    # Insert default COA
    c.execute("SELECT COUNT(*) FROM chart_of_accounts")
    if c.fetchone()[0] == 0:
        default_coa = [
            ('1-1010', 'Kas', 'Aset', 'Debit'),
            ('1-1020', 'Piutang Usaha', 'Aset', 'Debit'),
            ('1-1030', 'Persediaan Ikan', 'Aset', 'Debit'),
            ('1-2010', 'Peralatan Budidaya', 'Aset', 'Debit'),
            ('1-2020', 'Akumulasi Penyusutan Peralatan', 'Aset', 'Kredit'),
            ('2-1010', 'Utang Usaha', 'Liabilitas', 'Kredit'),
            ('3-1010', 'Modal Pemilik', 'Ekuitas', 'Kredit'),
            ('3-1020', 'Prive', 'Ekuitas', 'Debit'),
            ('3-1030', 'Ikhtisar Laba Rugi', 'Ekuitas', 'Kredit'),
            ('4-1010', 'Penjualan', 'Pendapatan', 'Kredit'),
            ('5-1010', 'Harga Pokok Penjualan', 'Beban', 'Debit'),
            ('5-1020', 'Beban Pakan', 'Beban', 'Debit'),
            ('5-1030', 'Beban Listrik', 'Beban', 'Debit'),
            ('5-1040', 'Beban Gaji', 'Beban', 'Debit'),
            ('5-1050', 'Beban Penyusutan', 'Beban', 'Debit'),
            ('5-1060', 'Beban Lain-lain', 'Beban', 'Debit'),
        ]
        c.executemany("INSERT INTO chart_of_accounts (kode_akun, nama_akun, kategori, saldo_normal) VALUES (?, ?, ?, ?)", default_coa)
        conn.commit()
    
    # Insert demo users
    demo_users = [
        ('demo_kasir', 'Demo123!', 'kasir', 'Demo Kasir', '081234567890'),
        ('demo_akuntan', 'Demo123!', 'akuntan', 'Demo Akuntan', '081234567891'),
        ('demo_owner', 'Demo123!', 'owner', 'Demo Owner', '081234567892'),
        ('demo_karyawan', 'Demo123!', 'karyawan', 'Demo Karyawan', '081234567893'),
    ]
    
    for username, password, role, nama, telp in demo_users:
        try:
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            if not c.fetchone():
                c.execute("""INSERT INTO users (username, password, role, nama_lengkap, no_telepon)
                            VALUES (?, ?, ?, ?, ?)""",
                         (username, hash_password(password), role, nama, telp))
                conn.commit()
        except:
            pass
    
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('Anda tidak memiliki akses ke halaman ini', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template_string(INDEX_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if not username or not password:
            flash('Username dan password harus diisi!', 'danger')
            return redirect(url_for('login'))
        
        conn = get_db()
        c = conn.cursor()
        hashed_pw = hash_password(password)
        
        c.execute("""SELECT id, username, role FROM users 
                    WHERE username=? AND password=? AND role=?""",
                 (username, hashed_pw, role))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Login berhasil! Selamat datang, {username}', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Username atau password salah, atau role tidak sesuai!', 'danger')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        nama_lengkap = request.form.get('nama_lengkap')
        no_telepon = request.form.get('no_telepon')
        
        if not username or not password:
            flash('Username dan password harus diisi!', 'danger')
            return redirect(url_for('register'))
        
        if len(username) < 4:
            flash('Username minimal 4 karakter!', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password minimal 6 karakter!', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Password tidak cocok!', 'danger')
            return redirect(url_for('register'))
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        if c.fetchone():
            flash('Username sudah digunakan!', 'danger')
            conn.close()
            return redirect(url_for('register'))
        
        try:
            hashed_pw = hash_password(password)
            c.execute("""INSERT INTO users (username, password, role, nama_lengkap, no_telepon)
                        VALUES (?, ?, ?, ?, ?)""",
                     (username, hashed_pw, role, nama_lengkap or None, no_telepon or None))
            conn.commit()
            conn.close()
            
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registrasi gagal: {e}', 'danger')
            conn.close()
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    
    if role == 'kasir':
        return redirect(url_for('kasir_dashboard'))
    elif role == 'akuntan':
        return redirect(url_for('akuntan_dashboard'))
    elif role == 'karyawan':
        return redirect(url_for('karyawan_dashboard'))
    elif role == 'owner':
        return redirect(url_for('owner_dashboard'))
    else:
        flash('Role tidak dikenali!', 'danger')
        return redirect(url_for('logout'))

# ==================== KASIR ROUTES ====================

@app.route('/kasir/dashboard')
@login_required
@role_required(['kasir'])
def kasir_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""SELECT COUNT(*), COALESCE(SUM(total), 0), COALESCE(SUM(jumlah_kg), 0)
                 FROM transaksi_penjualan 
                 WHERE kasir_id = ? AND tanggal = date('now')""",
             (session['user_id'],))
    stats = c.fetchone()
    
    c.execute("""SELECT no_struk, tanggal, waktu, jumlah_kg, total, metode_bayar 
                 FROM transaksi_penjualan 
                 WHERE kasir_id=? 
                 ORDER BY tanggal DESC, waktu DESC LIMIT 10""", 
             (session['user_id'],))
    transaksi = c.fetchall()
    
    conn.close()
    
    KASIR_DASHBOARD = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link active" href="/kasir/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link" href="/kasir/transaksi">
            <i class="bi bi-cart-plus"></i> Transaksi Penjualan
        </a>
        <a class="nav-link" href="/kasir/riwayat">
            <i class="bi bi-clock-history"></i> Riwayat Transaksi
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan Akun
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-speedometer2"></i> Dashboard Kasir</h2>
    </div>
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="metric-card success">
                <p>Transaksi Hari Ini</p>
                <h3>{{ stats[0] }}</h3>
                <small><i class="bi bi-receipt"></i> Total transaksi</small>
            </div>
        </div>
        <div class="col-md-4">
            <div class="metric-card info">
                <p>Total Penjualan</p>
                <h3>Rp {{ "{:,.0f}".format(stats[1]) }}</h3>
                <small><i class="bi bi-cash-coin"></i> Hari ini</small>
            </div>
        </div>
        <div class="col-md-4">
            <div class="metric-card warning">
                <p>Total Kg Terjual</p>
                <h3>{{ "{:.1f}".format(stats[2]) }} kg</h3>
                <small><i class="bi bi-box-seam"></i> Hari ini</small>
            </div>
        </div>
    </div>
    <div class="row mb-4">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-lightning-fill"></i> Quick Action
                </div>
                <div class="card-body">
                    <a href="/kasir/transaksi" class="btn btn-primary btn-lg">
                        <i class="bi bi-cart-plus"></i> Buat Transaksi Baru
                    </a>
                </div>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-clock-history"></i> Transaksi Terbaru
                </div>
                <div class="card-body">
                    {% if transaksi %}
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>No. Struk</th>
                                    <th>Tanggal</th>
                                    <th>Waktu</th>
                                    <th>Jumlah</th>
                                    <th>Total</th>
                                    <th>Metode Bayar</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for t in transaksi %}
                                <tr>
                                    <td><strong>{{ t.no_struk }}</strong></td>
                                    <td>{{ t.tanggal }}</td>
                                    <td>{{ t.waktu }}</td>
                                    <td>{{ "{:.1f}".format(t.jumlah_kg) }} kg</td>
                                    <td>Rp {{ "{:,.0f}".format(t.total) }}</td>
                                    <td><span class="badge bg-primary">{{ t.metode_bayar }}</span></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="text-center py-5">
                        <i class="bi bi-inbox display-1 text-muted"></i>
                        <p class="text-muted mt-3">Belum ada transaksi</p>
                    </div>
                    {% endif %}
                    <div class="text-end mt-3">
                        <a href="/kasir/riwayat" class="btn btn-outline-primary">
                            Lihat Semua <i class="bi bi-arrow-right"></i>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(KASIR_DASHBOARD, stats=stats, transaksi=transaksi)

@app.route('/kasir/transaksi', methods=['GET', 'POST'])
@login_required
@role_required(['kasir'])
def kasir_transaksi():
    if request.method == 'POST':
        data = request.get_json()
        cart = data.get('cart', [])
        metode_bayar = data.get('metode_bayar')
        
        if not cart:
            return jsonify({'success': False, 'message': 'Keranjang kosong!'}), 400
        
        total_kg = sum(item['jumlah_kg'] for item in cart)
        total_harga = sum(item['total'] for item in cart)
        
        conn = get_db()
        c = conn.cursor()
        
        try:
            now = datetime.now()
            no_struk = f"TRP{now.strftime('%Y%m%d%H%M%S')}"
            
            c.execute("""INSERT INTO transaksi_penjualan 
                        (no_struk, tanggal, waktu, jumlah_kg, harga_per_kg, total, metode_bayar, kasir_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                     (no_struk, now.date(), now.strftime('%H:%M:%S'), total_kg, 
                      total_harga/total_kg, total_harga, metode_bayar, session['user_id']))
            
            hpp_percentage = 0.6
            hpp = total_harga * hpp_percentage
            
            c.execute("""INSERT INTO jurnal_penjualan 
                        (tanggal, no_faktur, keterangan, debit_kas, kredit_penjualan, debit_hpp, kredit_persediaan)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (now.date(), no_struk, f"Penjualan ikan mujair {total_kg} kg", 
                      total_harga, total_harga, hpp, hpp))
            
            c.execute("SELECT saldo_jumlah, saldo_nilai FROM persediaan ORDER BY id DESC LIMIT 1")
            last_saldo = c.fetchone()
            
            if last_saldo:
                new_qty = last_saldo['saldo_jumlah'] - total_kg
                new_nilai = last_saldo['saldo_nilai'] - hpp
            else:
                new_qty = -total_kg
                new_nilai = -hpp
            
            c.execute("""INSERT INTO persediaan 
                        (tanggal, jenis_transaksi, jumlah, harga_satuan, total, saldo_jumlah, saldo_nilai)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                     (now.date(), "Penjualan", total_kg, hpp/total_kg, hpp, new_qty, new_nilai))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True, 
                'message': 'Transaksi berhasil!',
                'no_struk': no_struk,
                'total': total_harga
            })
            
        except Exception as e:
            conn.rollback()
            conn.close()
            return jsonify({'success': False, 'message': str(e)}), 500
    
    KASIR_TRANSAKSI = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link" href="/kasir/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link active" href="/kasir/transaksi">
            <i class="bi bi-cart-plus"></i> Transaksi Penjualan
        </a>
        <a class="nav-link" href="/kasir/riwayat">
            <i class="bi bi-clock-history"></i> Riwayat Transaksi
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan Akun
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-cart-plus"></i> Transaksi Penjualan</h2>
    </div>
    <div class="row">
        <div class="col-md-7">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-basket2"></i> Keranjang Belanja
                </div>
                <div class="card-body">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <label class="form-label">Harga per Kg (Rp)</label>
                            <input type="number" id="harga_per_kg" class="form-control" value="50000" min="0" step="1000">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Jumlah (Kg)</label>
                            <input type="number" id="jumlah_kg" class="form-control" value="1" min="0" step="0.5">
                        </div>
                    </div>
                    <button class="btn btn-success w-100 mb-3" onclick="tambahItem()">
                        <i class="bi bi-plus-circle"></i> Tambah ke Keranjang
                    </button>
                    <div id="cart-items" class="mb-3"></div>
                    <button class="btn btn-danger w-100" onclick="clearCart()">
                        <i class="bi bi-trash"></i> Kosongkan Keranjang
                    </button>
                </div>
            </div>
        </div>
        <div class="col-md-5">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-calculator"></i> Total Belanja
                </div>
                <div class="card-body">
                    <div class="mb-3">
                        <div class="d-flex justify-content-between mb-2">
                            <span>Total Kg:</span>
                            <strong id="total-kg">0 kg</strong>
                        </div>
                        <div class="d-flex justify-content-between mb-2">
                            <span>Total Harga:</span>
                            <strong class="text-primary" id="total-harga">Rp 0</strong>
                        </div>
                    </div>
                    <hr>
                    <div class="mb-3">
                        <label class="form-label">Metode Pembayaran</label>
                        <select id="metode_bayar" class="form-select">
                            <option value="Tunai">Tunai</option>
                            <option value="Kartu Debit">Kartu Debit</option>
                            <option value="Kartu Kredit">Kartu Kredit</option>
                            <option value="QRIS">QRIS</option>
                        </select>
                    </div>
                    <button class="btn btn-primary w-100" onclick="checkout()" id="btn-checkout" disabled>
                        <i class="bi bi-credit-card"></i> Cetak Struk
                    </button>
                </div>
            </div>
        </div>
    </div>
    <div class="modal fade" id="strukModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Struk Pembayaran</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="struk-content" style="font-family: monospace; padding: 20px; border: 2px solid #333;"></div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Tutup</button>
                    <button type="button" class="btn btn-primary" onclick="window.print()">
                        <i class="bi bi-printer"></i> Print
                    </button>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """).replace("{% block extra_js %}{% endblock %}", """
    {% block extra_js %}
    <script>
    let cart = [];
    function tambahItem() {
        const harga = parseFloat(document.getElementById('harga_per_kg').value);
        const jumlah = parseFloat(document.getElementById('jumlah_kg').value);
        if (jumlah <= 0) {
            alert('Jumlah harus lebih dari 0!');
            return;
        }
        cart.push({
            jumlah_kg: jumlah,
            harga_per_kg: harga,
            total: jumlah * harga
        });
        updateCart();
    }
    function hapusItem(index) {
        cart.splice(index, 1);
        updateCart();
    }
    function clearCart() {
        cart = [];
        updateCart();
    }
    function updateCart() {
        const cartDiv = document.getElementById('cart-items');
        if (cart.length === 0) {
            cartDiv.innerHTML = '<div class="alert alert-info">Keranjang kosong</div>';
            document.getElementById('btn-checkout').disabled = true;
        } else {
            let html = '<div class="list-group">';
            cart.forEach((item, index) => {
                html += `<div class="list-group-item d-flex justify-content-between align-items-center">
                    <div><strong>Item ${index + 1}</strong><br>
                    <small>${item.jumlah_kg} kg × Rp ${item.harga_per_kg.toLocaleString('id-ID')}</small></div>
                    <div class="text-end"><div>Rp ${item.total.toLocaleString('id-ID')}</div>
                    <button class="btn btn-sm btn-danger" onclick="hapusItem(${index})">
                        <i class="bi bi-trash"></i></button></div></div>`;
            });
            html += '</div>';
            cartDiv.innerHTML = html;
            document.getElementById('btn-checkout').disabled = false;
        }
        const totalKg = cart.reduce((sum, item) => sum + item.jumlah_kg, 0);
        const totalHarga = cart.reduce((sum, item) => sum + item.total, 0);
        document.getElementById('total-kg').textContent = totalKg.toFixed(1) + ' kg';
        document.getElementById('total-harga').textContent = 'Rp ' + totalHarga.toLocaleString('id-ID');
    }
    function checkout() {
        if (cart.length === 0) {
            alert('Keranjang kosong!');
            return;
        }
        const metode = document.getElementById('metode_bayar').value;
        fetch('/kasir/transaksi', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({cart: cart, metode_bayar: metode})
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showStruk(data);
                clearCart();
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            alert('Error: ' + error);
        });
    }
    function showStruk(data) {
        const totalKg = cart.reduce((sum, item) => sum + item.jumlah_kg, 0);
        const now = new Date();
        const strukHtml = `
            <div style="text-align: center;">
                <h4>🐟 TILAPIA SUITE</h4>
                <p style="margin: 5px 0;">Budidaya Ikan Mujair Premium</p>
                <p style="margin: 5px 0;">Jl. Perikanan No. 123, Semarang</p>
                <p style="margin: 5px 0;">Telp: (024) 123-4567</p>
            </div><hr>
            <p><strong>No. Struk:</strong> ${data.no_struk}</p>
            <p><strong>Tanggal:</strong> ${now.toLocaleDateString('id-ID')}</p>
            <p><strong>Waktu:</strong> ${now.toLocaleTimeString('id-ID')}</p>
            <p><strong>Kasir:</strong> {{ session.username }}</p><hr>
            <p><strong>DETAIL PEMBELIAN</strong></p>
            <p>Ikan Mujair Segar</p>
            <p>${totalKg.toFixed(1)} kg × Rp ${(data.total / totalKg).toLocaleString('id-ID')}</p><hr>
            <p style="font-size: 18px;"><strong>TOTAL: Rp ${data.total.toLocaleString('id-ID')}</strong></p>
            <p><strong>Metode Bayar:</strong> ${document.getElementById('metode_bayar').value}</p><hr>
            <div style="text-align: center;">
                <p>Terima kasih atas kunjungan Anda!</p>
                <p>Selamat menikmati! 🐟</p>
            </div>`;
        document.getElementById('struk-content').innerHTML = strukHtml;
        new bootstrap.Modal(document.getElementById('strukModal')).show();
    }
    updateCart();
    </script>
    {% endblock %}
    """)
    
    return render_template_string(KASIR_TRANSAKSI)

@app.route('/kasir/riwayat')
@login_required
@role_required(['kasir'])
def kasir_riwayat():
    conn = get_db()
    c = conn.cursor()
    
    dari_tanggal = request.args.get('dari', '')
    sampai_tanggal = request.args.get('sampai', '')
    
    query = """SELECT no_struk, tanggal, waktu, jumlah_kg, total, metode_bayar 
               FROM transaksi_penjualan 
               WHERE kasir_id=?"""
    params = [session['user_id']]
    
    if dari_tanggal:
        query += " AND tanggal >= ?"
        params.append(dari_tanggal)
    if sampai_tanggal:
        query += " AND tanggal <= ?"
        params.append(sampai_tanggal)
    
    query += " ORDER BY tanggal DESC, waktu DESC LIMIT 100"
    
    c.execute(query, params)
    transaksi = c.fetchall()
    
    total_transaksi = len(transaksi)
    total_kg = sum([t['jumlah_kg'] for t in transaksi])
    total_nilai = sum([t['total'] for t in transaksi])
    
    conn.close()
    
    KASIR_RIWAYAT = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link" href="/kasir/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link" href="/kasir/transaksi">
            <i class="bi bi-cart-plus"></i> Transaksi Penjualan
        </a>
        <a class="nav-link active" href="/kasir/riwayat">
            <i class="bi bi-clock-history"></i> Riwayat Transaksi
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan Akun
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-clock-history"></i> Riwayat Transaksi</h2>
    </div>
    <div class="card mb-4">
        <div class="card-header">
            <i class="bi bi-funnel"></i> Filter & Pencarian
        </div>
        <div class="card-body">
            <form method="GET" action="/kasir/riwayat">
                <div class="row g-3">
                    <div class="col-md-4">
                        <label class="form-label">Tanggal Mulai</label>
                        <input type="date" name="dari" class="form-control" value="{{ dari_tanggal }}">
                    </div>
                    <div class="col-md-4">
                        <label class="form-label">Tanggal Akhir</label>
                        <input type="date" name="sampai" class="form-control" value="{{ sampai_tanggal }}">
                    </div>
                    <div class="col-md-4">
                        <label class="form-label">&nbsp;</label>
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-search"></i> Cari
                        </button>
                    </div>
                </div>
            </form>
        </div>
    </div>
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="metric-card success">
                <p>Total Transaksi</p>
                <h3>{{ total_transaksi }}</h3>
                <small><i class="bi bi-receipt"></i> Semua transaksi</small>
            </div>
        </div>
        <div class="col-md-4">
            <div class="metric-card info">
                <p>Total Kg Terjual</p>
                <h3>{{ "{:.1f}".format(total_kg) }} kg</h3>
                <small><i class="bi bi-box-seam"></i> Total berat</small>
            </div>
        </div>
        <div class="col-md-4">
            <div class="metric-card warning">
                <p>Total Nilai</p>
                <h3>Rp {{ "{:,.0f}".format(total_nilai) }}</h3>
                <small><i class="bi bi-cash-coin"></i> Total pendapatan</small>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <span><i class="bi bi-table"></i> Daftar Transaksi</span>
            <span class="badge bg-primary">{{ transaksi|length }} transaksi</span>
        </div>
        <div class="card-body">
            {% if transaksi %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>No. Struk</th>
                            <th>Tanggal</th>
                            <th>Waktu</th>
                            <th>Jumlah (Kg)</th>
                            <th>Total</th>
                            <th>Metode Bayar</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for t in transaksi %}
                        <tr>
                            <td><strong>{{ t.no_struk }}</strong></td>
                            <td>{{ t.tanggal }}</td>
                            <td>{{ t.waktu }}</td>
                            <td>{{ "{:.1f}".format(t.jumlah_kg) }} kg</td>
                            <td><strong class="text-success">Rp {{ "{:,.0f}".format(t.total) }}</strong></td>
                            <td><span class="badge bg-primary">{{ t.metode_bayar }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="text-center py-5">
                <i class="bi bi-inbox display-1 text-muted"></i>
                <p class="text-muted mt-3">Tidak ada transaksi ditemukan</p>
                <a href="/kasir/transaksi" class="btn btn-primary">
                    <i class="bi bi-cart-plus"></i> Buat Transaksi Baru
                </a>
            </div>
            {% endif %}
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(KASIR_RIWAYAT, transaksi=transaksi, total_transaksi=total_transaksi, 
                                 total_kg=total_kg, total_nilai=total_nilai, 
                                 dari_tanggal=dari_tanggal, sampai_tanggal=sampai_tanggal)

# ==================== AKUNTAN ROUTES ====================

@app.route('/akuntan/dashboard')
@login_required
@role_required(['akuntan'])
def akuntan_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""SELECT COALESCE(SUM(total), 0) FROM transaksi_penjualan 
                 WHERE strftime('%Y-%m', tanggal) = strftime('%Y-%m', 'now')""")
    penjualan = c.fetchone()[0]
    
    c.execute("""SELECT COALESCE(SUM(debit_hpp), 0) FROM jurnal_penjualan 
                 WHERE strftime('%Y-%m', tanggal) = strftime('%Y-%m', 'now')""")
    hpp = c.fetchone()[0]
    
    c.execute("""SELECT COALESCE(SUM(nominal), 0) FROM biaya 
                 WHERE strftime('%Y-%m', tanggal) = strftime('%Y-%m', 'now')""")
    biaya = c.fetchone()[0]
    
    laba_kotor = penjualan - hpp
    
    conn.close()
    
    AKUNTAN_DASHBOARD = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link active" href="/akuntan/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link" href="/akuntan/coa">
            <i class="bi bi-list-ul"></i> Chart of Accounts
        </a>
        <a class="nav-link" href="/akuntan/jurnal">
            <i class="bi bi-journal-text"></i> Jurnal
        </a>
        <a class="nav-link" href="/akuntan/buku-besar">
            <i class="bi bi-book"></i> Buku Besar
        </a>
        <a class="nav-link" href="/akuntan/laporan">
            <i class="bi bi-file-earmark-text"></i> Laporan Keuangan
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-speedometer2"></i> Dashboard Akuntan</h2>
    </div>
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="metric-card success">
                <p>Penjualan Bulan Ini</p>
                <h3>Rp {{ "{:,.0f}".format(penjualan) }}</h3>
                <small><i class="bi bi-cash-coin"></i> Revenue</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card danger">
                <p>HPP Bulan Ini</p>
                <h3>Rp {{ "{:,.0f}".format(hpp) }}</h3>
                <small><i class="bi bi-box-seam"></i> Cost of Goods</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card warning">
                <p>Biaya Operasional</p>
                <h3>Rp {{ "{:,.0f}".format(biaya) }}</h3>
                <small><i class="bi bi-credit-card"></i> Expenses</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="metric-card info">
                <p>Laba Kotor</p>
                <h3>Rp {{ "{:,.0f}".format(laba_kotor) }}</h3>
                <small><i class="bi bi-trophy"></i> Gross Profit</small>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-info-circle"></i> Informasi
                </div>
                <div class="card-body">
                    <p>Selamat datang di dashboard akuntan. Gunakan menu di samping untuk mengakses fitur akuntansi.</p>
                    <div class="row g-3 mt-3">
                        <div class="col-md-4">
                            <a href="/akuntan/jurnal" class="btn btn-outline-primary w-100">
                                <i class="bi bi-journal-text"></i> Input Jurnal
                            </a>
                        </div>
                        <div class="col-md-4">
                            <a href="/akuntan/buku-besar" class="btn btn-outline-success w-100">
                                <i class="bi bi-book"></i> Lihat Buku Besar
                            </a>
                        </div>
                        <div class="col-md-4">
                            <a href="/akuntan/laporan" class="btn btn-outline-info w-100">
                                <i class="bi bi-file-earmark-text"></i> Laporan Keuangan
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(AKUNTAN_DASHBOARD, penjualan=penjualan, hpp=hpp, 
                                 biaya=biaya, laba_kotor=laba_kotor)

@app.route('/akuntan/coa')
@login_required
@role_required(['akuntan'])
def akuntan_coa():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM chart_of_accounts ORDER BY kode_akun")
    coa = c.fetchall()
    conn.close()
    
    AKUNTAN_COA = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link" href="/akuntan/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link active" href="/akuntan/coa">
            <i class="bi bi-list-ul"></i> Chart of Accounts
        </a>
        <a class="nav-link" href="/akuntan/jurnal">
            <i class="bi bi-journal-text"></i> Jurnal
        </a>
        <a class="nav-link" href="/akuntan/buku-besar">
            <i class="bi bi-book"></i> Buku Besar
        </a>
        <a class="nav-link" href="/akuntan/laporan">
            <i class="bi bi-file-earmark-text"></i> Laporan Keuangan
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-list-ul"></i> Chart of Accounts</h2>
    </div>
    <div class="card">
        <div class="card-header">
            <i class="bi bi-table"></i> Daftar Akun
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Kode Akun</th>
                            <th>Nama Akun</th>
                            <th>Kategori</th>
                            <th>Saldo Normal</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for akun in coa %}
                        <tr>
                            <td><strong>{{ akun.kode_akun }}</strong></td>
                            <td>{{ akun.nama_akun }}</td>
                            <td><span class="badge 
                                {% if akun.kategori == 'Aset' %}bg-primary
                                {% elif akun.kategori == 'Liabilitas' %}bg-danger
                                {% elif akun.kategori == 'Ekuitas' %}bg-warning
                                {% elif akun.kategori == 'Pendapatan' %}bg-success
                                {% else %}bg-info{% endif %}">
                                {{ akun.kategori }}
                            </span></td>
                            <td>{{ akun.saldo_normal }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(AKUNTAN_COA, coa=coa)

# ==================== OWNER ROUTES ====================

@app.route('/owner/dashboard')
@login_required
@role_required(['owner'])
def owner_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""SELECT COALESCE(SUM(total), 0) FROM transaksi_penjualan 
                 WHERE tanggal = date('now')""")
    penjualan_hari_ini = c.fetchone()[0]
    
    c.execute("""SELECT COALESCE(SUM(total), 0) FROM transaksi_penjualan 
                 WHERE strftime('%Y-%m', tanggal) = strftime('%Y-%m', 'now')""")
    penjualan_bulan_ini = c.fetchone()[0]
    
    c.execute("""SELECT COALESCE(SUM(nominal), 0) FROM biaya 
                 WHERE strftime('%Y-%m', tanggal) = strftime('%Y-%m', 'now')""")
    biaya_bulan_ini = c.fetchone()[0]
    
    laba_bulan_ini = penjualan_bulan_ini * 0.4 - biaya_bulan_ini
    
    conn.close()
    
    OWNER_DASHBOARD = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link active" href="/owner/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-briefcase"></i> Dashboard Owner</h2>
    </div>
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card border-0 shadow-sm">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <p class="text-muted mb-1">Penjualan Hari Ini</p>
                            <h3 class="mb-0">Rp {{ "{:,.0f}".format(penjualan_hari_ini) }}</h3>
                        </div>
                        <div class="bg-success bg-opacity-10 p-3 rounded">
                            <i class="bi bi-cash-coin text-success" style="font-size: 2rem;"></i>
                        </div>
                    </div>
                    <small class="text-success">
                        <i class="bi bi-arrow-up"></i> Today's sales
                    </small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-0 shadow-sm">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <p class="text-muted mb-1">Penjualan Bulan Ini</p>
                            <h3 class="mb-0">Rp {{ "{:,.0f}".format(penjualan_bulan_ini) }}</h3>
                        </div>
                        <div class="bg-primary bg-opacity-10 p-3 rounded">
                            <i class="bi bi-graph-up text-primary" style="font-size: 2rem;"></i>
                        </div>
                    </div>
                    <small class="text-primary">
                        <i class="bi bi-calendar"></i> This month
                    </small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-0 shadow-sm">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <p class="text-muted mb-1">Biaya Bulan Ini</p>
                            <h3 class="mb-0">Rp {{ "{:,.0f}".format(biaya_bulan_ini) }}</h3>
                        </div>
                        <div class="bg-warning bg-opacity-10 p-3 rounded">
                            <i class="bi bi-credit-card text-warning" style="font-size: 2rem;"></i>
                        </div>
                    </div>
                    <small class="text-warning">
                        <i class="bi bi-arrow-down"></i> Expenses
                    </small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-0 shadow-sm">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <p class="text-muted mb-1">Est. Laba Bulan Ini</p>
                            <h3 class="mb-0 {% if laba_bulan_ini > 0 %}text-success{% else %}text-danger{% endif %}">
                                Rp {{ "{:,.0f}".format(laba_bulan_ini) }}
                            </h3>
                        </div>
                        <div class="bg-info bg-opacity-10 p-3 rounded">
                            <i class="bi bi-trophy text-info" style="font-size: 2rem;"></i>
                        </div>
                    </div>
                    <small class="{% if laba_bulan_ini > 0 %}text-success{% else %}text-danger{% endif %}">
                        <i class="bi bi-{% if laba_bulan_ini > 0 %}arrow-up{% else %}arrow-down{% endif %}"></i> 
                        Net profit
                    </small>
                </div>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-info-circle"></i> Ringkasan Bisnis
                </div>
                <div class="card-body">
                    <p>Selamat datang, Owner! Berikut adalah ringkasan performa bisnis Anda.</p>
                    <div class="alert alert-info">
                        <strong>Tips:</strong> Monitor penjualan dan biaya secara rutin untuk menjaga profitabilitas usaha.
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(OWNER_DASHBOARD, 
                                 penjualan_hari_ini=penjualan_hari_ini,
                                 penjualan_bulan_ini=penjualan_bulan_ini,
                                 biaya_bulan_ini=biaya_bulan_ini,
                                 laba_bulan_ini=laba_bulan_ini)

# ==================== KARYAWAN ROUTES ====================

@app.route('/karyawan/dashboard')
@login_required
@role_required(['karyawan'])
def karyawan_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""SELECT COUNT(*), COALESCE(SUM(total), 0) 
                 FROM pembelian_karyawan 
                 WHERE karyawan_id = ? AND strftime('%Y-%m', tanggal) = strftime('%Y-%m', 'now')""",
             (session['user_id'],))
    stats = c.fetchone()
    
    conn.close()
    
    KARYAWAN_DASHBOARD = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        <a class="nav-link active" href="/karyawan/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan Akun
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-tools"></i> Dashboard Karyawan</h2>
    </div>
    <div class="row mb-4">
        <div class="col-md-6">
            <div class="metric-card success">
                <p>Transaksi Bulan Ini</p>
                <h3>{{ stats[0] }}</h3>
                <small><i class="bi bi-receipt"></i> Total pembelian yang diinput</small>
            </div>
        </div>
        <div class="col-md-6">
            <div class="metric-card info">
                <p>Total Pembelian Bulan Ini</p>
                <h3>Rp {{ "{:,.0f}".format(stats[1]) }}</h3>
                <small><i class="bi bi-cash-stack"></i> Total nilai pembelian</small>
            </div>
        </div>
    </div>
    <div class="row mb-4">
        <div class="col-12">
            <div class="alert alert-info">
                <h5><i class="bi bi-info-circle"></i> Informasi</h5>
                <ul class="mb-0">
                    <li>Setiap pembelian yang Anda input akan otomatis tercatat di sistem akuntansi</li>
                    <li>Pembelian benih akan menambah persediaan ikan</li>
                    <li>Pembelian pakan dan bahan akan tercatat sebagai biaya operasional</li>
                    <li>Pastikan menyimpan nota/kwitansi untuk dokumentasi</li>
                </ul>
            </div>
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(KARYAWAN_DASHBOARD, stats=stats if stats else (0, 0))

# ==================== SETTINGS ROUTE ====================

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    conn = get_db()
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            nama_lengkap = request.form.get('nama_lengkap')
            no_telepon = request.form.get('no_telepon')
            alamat = request.form.get('alamat')
            
            c.execute("""UPDATE users SET nama_lengkap=?, no_telepon=?, alamat=? 
                        WHERE id=?""",
                     (nama_lengkap, no_telepon, alamat, session['user_id']))
            conn.commit()
            flash('Profil berhasil diperbarui!', 'success')
            
        elif action == 'change_password':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not old_password or not new_password:
                flash('Semua field harus diisi!', 'danger')
            elif new_password != confirm_password:
                flash('Password baru tidak cocok!', 'danger')
            elif len(new_password) < 6:
                flash('Password baru minimal 6 karakter!', 'danger')
            else:
                hashed_old = hash_password(old_password)
                c.execute("SELECT id FROM users WHERE id=? AND password=?", 
                         (session['user_id'], hashed_old))
                
                if not c.fetchone():
                    flash('Password lama salah!', 'danger')
                else:
                    hashed_new = hash_password(new_password)
                    c.execute("UPDATE users SET password=? WHERE id=?", 
                             (hashed_new, session['user_id']))
                    conn.commit()
                    flash('Password berhasil diubah! Silakan login kembali.', 'success')
                    conn.close()
                    return redirect(url_for('logout'))
    
    c.execute("""SELECT username, role, nama_lengkap, no_telepon, alamat 
                 FROM users WHERE id=?""", (session['user_id'],))
    user_data = c.fetchone()
    conn.close()
    
    SETTINGS_TEMPLATE = BASE_TEMPLATE.replace("{% block sidebar %}{% endblock %}", """
    {% block sidebar %}
    <nav class="nav flex-column">
        {% if session.role == 'kasir' %}
        <a class="nav-link" href="/kasir/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        {% elif session.role == 'akuntan' %}
        <a class="nav-link" href="/akuntan/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        {% elif session.role == 'karyawan' %}
        <a class="nav-link" href="/karyawan/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        {% elif session.role == 'owner' %}
        <a class="nav-link" href="/owner/dashboard">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        {% endif %}
        <a class="nav-link active" href="/settings">
            <i class="bi bi-gear"></i> Pengaturan Akun
        </a>
    </nav>
    {% endblock %}
    """).replace("{% block content %}{% endblock %}", """
    {% block content %}
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-gear"></i> Pengaturan Akun</h2>
    </div>
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <i class="bi bi-person-circle"></i> Informasi Akun
                </div>
                <div class="card-body text-center">
                    <div class="mb-3">
                        <i class="bi bi-person-circle display-1 text-primary"></i>
                    </div>
                    <h5>{{ session.username }}</h5>
                    <span class="badge bg-primary mb-3">{{ session.role|upper }}</span>
                    <hr>
                    <div class="text-start">
                        <p class="mb-2"><strong>Username:</strong> {{ session.username }}</p>
                        <p class="mb-2"><strong>Role:</strong> {{ session.role }}</p>
                        <p class="mb-0"><strong>Status:</strong> <span class="badge bg-success">Aktif</span></p>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-md-8">
            <div class="card mb-3">
                <div class="card-header">
                    <i class="bi bi-pencil-square"></i> Edit Profil
                </div>
                <div class="card-body">
                    <form method="POST" action="/settings">
                        <input type="hidden" name="action" value="update_profile">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label class="form-label">Nama Lengkap</label>
                                <input type="text" name="nama_lengkap" class="form-control" 
                                       value="{{ user_data.nama_lengkap or '' }}" 
                                       placeholder="Masukkan nama lengkap">
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">No. Telepon</label>
                                <input type="text" name="no_telepon" class="form-control" 
                                       value="{{ user_data.no_telepon or '' }}" 
                                       placeholder="08xxxxxxxxxx">
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Alamat</label>
                            <textarea name="alamat" class="form-control" rows="3" 
                                      placeholder="Masukkan alamat lengkap">{{ user_data.alamat or '' }}</textarea>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-check-circle"></i> Simpan Perubahan
                        </button>
                    </form>
                </div>
            </div>
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-shield-lock"></i> Ubah Password
                </div>
                <div class="card-body">
                    <form method="POST" action="/settings" id="changePasswordForm">
                        <input type="hidden" name="action" value="change_password">
                        <div class="mb-3">
                            <label class="form-label">Password Lama</label>
                            <input type="password" name="old_password" class="form-control" 
                                   id="old_password" required placeholder="Masukkan password lama">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Password Baru</label>
                            <input type="password" name="new_password" class="form-control" 
                                   id="new_password" required placeholder="Minimal 6 karakter">
                            <small class="text-muted">Gunakan kombinasi huruf, angka, dan simbol</small>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Konfirmasi Password Baru</label>
                            <input type="password" name="confirm_password" class="form-control" 
                                   id="confirm_password" required placeholder="Ketik ulang password baru">
                        </div>
                        <div class="alert alert-warning">
                            <i class="bi bi-exclamation-triangle"></i>
                            Setelah mengubah password, Anda akan otomatis logout dan harus login kembali.
                        </div>
                        <button type="submit" class="btn btn-warning">
                            <i class="bi bi-shield-lock"></i> Ubah Password
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """)
    
    return render_template_string(SETTINGS_TEMPLATE, user_data=user_data)

# ==================== API ROUTES ====================

@app.route('/api/chart_data/<chart_type>')
@login_required
def get_chart_data(chart_type):
    conn = get_db()
    c = conn.cursor()
    
    if chart_type == 'penjualan_30_hari':
        c.execute("""SELECT tanggal, SUM(total) as total
                     FROM transaksi_penjualan 
                     WHERE tanggal >= date('now', '-30 days')
                     GROUP BY tanggal ORDER BY tanggal""")
        data = [{'tanggal': row['tanggal'], 'total': row['total']} for row in c.fetchall()]
    else:
        data = []
    
    conn.close()
    return jsonify(data)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
    
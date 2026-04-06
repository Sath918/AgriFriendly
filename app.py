from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, make_response
import sqlite3, csv, io, os
import base64, json, hmac, hashlib
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
DB_NAME = "agri_db_v2.sqlite"
SECRET_KEY = "AgriFriendlySuperSecretKey"

def encode_jwt(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{signing_input}.{signature_b64}"

def decode_jwt(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
        if not hmac.compare_digest(signature_b64, expected_sig_b64):
            return None
        payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded).decode())
        if "exp" in payload and payload["exp"] < datetime.utcnow().timestamp():
            return None
        return payload
    except Exception:
        return None

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, profile_pic TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS budget
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  name TEXT,
                  season TEXT,
                  limit_amount REAL,
                  status TEXT DEFAULT 'active',
                  created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS expenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  budget_id INTEGER,
                  date TEXT,
                  category TEXT,
                  amount REAL,
                  notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS incomes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  budget_id INTEGER,
                  date TEXT,
                  source TEXT,
                  amount REAL,
                  notes TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tips
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  author TEXT,
                  content TEXT,
                  created_at TEXT)''')
    conn.commit()
    conn.close()

init_db()

def query_db(q, args=(), one=False, execute=False):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(q, args)
    if execute:
        conn.commit()
        last_id = cur.lastrowid
        conn.close()
        return last_id
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("jwt_token")
        if not token:
            return redirect(url_for('login'))
        payload = decode_jwt(token)
        if not payload or "user_id" not in payload:
            return redirect(url_for('login'))
        request.user_id = payload["user_id"]
        request.username = payload.get("username", "Farmer")
        user = query_db("SELECT profile_pic FROM users WHERE id=?", (request.user_id,), one=True)
        request.user_profile_pic = user[0] if user and user[0] else None
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
        if user and check_password_hash(user[2], password):
            payload = {"user_id": user[0], "username": user[1], "exp": (datetime.utcnow() + timedelta(days=7)).timestamp()}
            token = encode_jwt(payload)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie("jwt_token", token, httponly=True)
            return resp
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
        if existing:
            return render_template("register.html", error="Username exists")
        hashed = generate_password_hash(password)
        user_id = query_db("INSERT INTO users (username, password) VALUES (?,?)", (username, hashed), execute=True)
        payload = {"user_id": user_id, "username": username, "exp": (datetime.utcnow() + timedelta(days=7)).timestamp()}
        token = encode_jwt(payload)
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie("jwt_token", token, httponly=True)
        return resp
    return render_template("register.html")

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie("jwt_token", "", expires=0)
    return resp

@app.route('/')
@login_required
def dashboard():
    budget = query_db("SELECT * FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    budget_id = budget[0] if budget else None
    
    if budget_id:
        expenses = query_db("SELECT * FROM expenses WHERE user_id=? AND budget_id=? ORDER BY date DESC, id DESC", (request.user_id, budget_id))
        incomes = query_db("SELECT * FROM incomes WHERE user_id=? AND budget_id=? ORDER BY date DESC, id DESC", (request.user_id, budget_id))
    else:
        expenses = []
        incomes = []

    total_exp = sum([row[5] for row in expenses]) if expenses else 0
    total_inc = sum([row[5] for row in incomes]) if incomes else 0
    profit = total_inc - total_exp
    
    cat_data = {}
    for r in expenses:
        cat_data[r[4]] = cat_data.get(r[4], 0) + r[5]
    labels = list(cat_data.keys())
    values = list(cat_data.values())

    month_map = {}
    for r in expenses:
        m = r[3][:7]
        if m not in month_map: month_map[m] = {'income':0, 'expense':0}
        month_map[m]['expense'] += r[5]
    for r in incomes:
        m = r[3][:7]
        if m not in month_map: month_map[m] = {'income':0, 'expense':0}
        month_map[m]['income'] += r[5]
    
    months = sorted(month_map.keys())
    inc_series = [month_map[m]['income'] for m in months]
    exp_series = [month_map[m]['expense'] for m in months]

    return render_template("dashboard.html",
                           total_exp=total_exp,
                           total_inc=total_inc,
                           profit=profit,
                           labels=labels, values=values,
                           months=months, inc_series=inc_series, exp_series=exp_series,
                           budget=budget, username=request.username,
                           recent_expenses=expenses[:3], recent_incomes=incomes[:3])

@app.route('/end_season', methods=['POST'])
@login_required
def end_season():
    query_db("UPDATE budget SET status='archived' WHERE user_id=?", (request.user_id,), execute=True)
    return redirect(url_for('dashboard'))

@app.route('/new_budget', methods=['POST'])
@login_required
def new_budget():
    query_db("UPDATE budget SET status='archived' WHERE user_id=?", (request.user_id,), execute=True)
    name = request.form.get('name') or "Fresh Budget"
    season = request.form.get('season') or "Samba"
    limit_amount = float(request.form.get('limit_amount') or 0)
    created_at = datetime.now().isoformat()
    query_db("INSERT INTO budget (user_id, name, season, limit_amount, status, created_at) VALUES (?,?,?,?,?,?)",
             (request.user_id, name, season, limit_amount, 'active', created_at), execute=True)
    return redirect(url_for('dashboard'))

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    budget = query_db("SELECT id FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    if not budget: return redirect(url_for('dashboard'))
    date = request.form.get('date') or datetime.today().date().isoformat()
    category = request.form.get('category')
    amount = float(request.form.get('amount') or 0)
    notes = request.form.get('notes')
    query_db("INSERT INTO expenses (user_id, budget_id, date, category, amount, notes) VALUES (?,?,?,?,?,?)",
             (request.user_id, budget[0], date, category, amount, notes), execute=True)
    return redirect(url_for('dashboard'))

@app.route('/expenses')
@login_required
def view_expenses():
    budget = query_db("SELECT id FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    b_id = budget[0] if budget else -1
    data = query_db("SELECT * FROM expenses WHERE user_id=? AND budget_id=? ORDER BY date DESC", (request.user_id, b_id))
    total = sum(r[5] for r in data)
    return render_template("view_expenses.html", expenses=data, total=total)

@app.route('/delete_expense/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_expense(id):
    query_db("DELETE FROM expenses WHERE id=? AND user_id=?", (id, request.user_id), execute=True)
    return redirect(request.referrer or url_for('view_expenses'))

@app.route('/edit_expense/<int:id>', methods=['POST'])
@login_required
def edit_expense(id):
    date = request.form.get('date')
    category = request.form.get('category')
    amount = float(request.form.get('amount') or 0)
    notes = request.form.get('notes')
    query_db("UPDATE expenses SET date=?, category=?, amount=?, notes=? WHERE id=? AND user_id=?", 
             (date, category, amount, notes, id, request.user_id), execute=True)
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/add_income', methods=['POST'])
@login_required
def add_income():
    budget = query_db("SELECT id FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    if not budget: return redirect(url_for('dashboard'))
    date = request.form.get('date') or datetime.today().date().isoformat()
    source = request.form.get('source')
    amount = float(request.form.get('amount') or 0)
    notes = request.form.get('notes')
    query_db("INSERT INTO incomes (user_id, budget_id, date, source, amount, notes) VALUES (?,?,?,?,?,?)",
             (request.user_id, budget[0], date, source, amount, notes), execute=True)
    return redirect(url_for('dashboard'))

@app.route('/incomes')
@login_required
def view_incomes():
    budget = query_db("SELECT id FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    b_id = budget[0] if budget else -1
    data = query_db("SELECT * FROM incomes WHERE user_id=? AND budget_id=? ORDER BY date DESC", (request.user_id, b_id))
    total = sum(r[5] for r in data)
    return render_template("view_incomes.html", incomes=data, total=total)

@app.route('/delete_income/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_income(id):
    query_db("DELETE FROM incomes WHERE id=? AND user_id=?", (id, request.user_id), execute=True)
    return redirect(request.referrer or url_for('view_incomes'))

@app.route('/edit_income/<int:id>', methods=['POST'])
@login_required
def edit_income(id):
    date = request.form.get('date')
    source = request.form.get('source')
    amount = float(request.form.get('amount') or 0)
    notes = request.form.get('notes')
    query_db("UPDATE incomes SET date=?, source=?, amount=?, notes=? WHERE id=? AND user_id=?", 
             (date, source, amount, notes, id, request.user_id), execute=True)
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/upload_profile', methods=['POST'])
@login_required
def upload_profile():
    if 'profile_pic' not in request.files:
        return redirect(request.referrer or url_for('dashboard'))
    file = request.files['profile_pic']
    if file.filename == '':
        return redirect(request.referrer or url_for('dashboard'))
    
    if file:
        filename = f"profile_{request.user_id}_{int(datetime.now().timestamp())}.png"
        path = os.path.join('static', 'uploads', 'profiles', filename)
        file.save(path)
        query_db("UPDATE users SET profile_pic=? WHERE id=?", (filename, request.user_id), execute=True)
        # Update current user profile pic in request
        request.user_profile_pic = filename 
        
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    new_username = request.form.get('username')
    new_password = request.form.get('password')
    
    if not new_username:
        return redirect(request.referrer or url_for('dashboard'))
        
    # Check if username is taken by someone else
    existing = query_db("SELECT id FROM users WHERE username=? AND id != ?", (new_username, request.user_id), one=True)
    if existing:
        # In a real app we'd pass an error message via flash or similar
        return redirect(request.referrer or url_for('dashboard'))

    if new_password:
        hashed = generate_password_hash(new_password)
        query_db("UPDATE users SET username=?, password=? WHERE id=?", (new_username, hashed, request.user_id), execute=True)
    else:
        query_db("UPDATE users SET username=? WHERE id=?", (new_username, request.user_id), execute=True)
    
    # We should ideally regenerate the token if username changed, but for simplicity we'll just redirect
    # Since the token is checked every request and contains the old username, update_jwt logic would be better
    # But for this task, basic update is requested.
    
    return redirect(url_for('logout')) # Force re-login with new credentials

@app.route('/tips', methods=['GET', 'POST'])
def tips():
    if request.method == 'POST':
        author = request.form.get('author') or 'Anonymous'
        content = request.form.get('content')
        created_at = datetime.now().isoformat()
        query_db("INSERT INTO tips (author, content, created_at) VALUES (?,?,?)",
                 (author, content, created_at), execute=True)
        return redirect(url_for('tips'))
    data = query_db("SELECT * FROM tips ORDER BY created_at DESC")
    return render_template("tips.html", tips=data)

@app.route('/export/csv')
@login_required
def export_csv():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['type','id','date','category/source','amount','notes'])
    budget = query_db("SELECT id FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    if budget:
        b_id = budget[0]
        exps = query_db("SELECT id, date, category, amount, notes FROM expenses WHERE user_id=? AND budget_id=?", (request.user_id, b_id))
        for r in exps: cw.writerow(['expense', r[0], r[1], r[2], r[3], r[4]])
        incs = query_db("SELECT id, date, source, amount, notes FROM incomes WHERE user_id=? AND budget_id=?", (request.user_id, b_id))
        for r in incs: cw.writerow(['income', r[0], r[1], r[2], r[3], r[4]])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    filename = f"agri_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(output, mimetype='text/csv', download_name=filename, as_attachment=True)

@app.route('/history')
@login_required
def history():
    budgets = query_db("SELECT * FROM budget WHERE user_id=? AND status='archived' ORDER BY id DESC", (request.user_id,))
    history_data = []
    for b in budgets:
        expenses = query_db("SELECT amount FROM expenses WHERE budget_id=?", (b[0],))
        incomes = query_db("SELECT amount FROM incomes WHERE budget_id=?", (b[0],))
        t_exp = sum([x[0] for x in expenses]) if expenses else 0
        t_inc = sum([x[0] for x in incomes]) if incomes else 0
        history_data.append({'budget': b, 'total_exp': t_exp, 'total_inc': t_inc, 'profit': t_inc - t_exp})
    return render_template("history.html", history_data=history_data)

@app.route('/export/pdf')
@login_required
def export_pdf():
    budget = query_db("SELECT * FROM budget WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (request.user_id,), one=True)
    if not budget: return redirect(url_for('dashboard'))
    exps = query_db("SELECT * FROM expenses WHERE user_id=? AND budget_id=? ORDER BY date DESC", (request.user_id, budget[0]))
    incs = query_db("SELECT * FROM incomes WHERE user_id=? AND budget_id=? ORDER BY date DESC", (request.user_id, budget[0]))
    t_exp = sum([x[5] for x in exps]) if exps else 0
    t_inc = sum([x[5] for x in incs]) if incs else 0
    return render_template("export_pdf.html", budget=budget, expenses=exps, incomes=incs, total_exp=t_exp, total_inc=t_inc)

if __name__ == '__main__':
    app.run(debug=True, port=5000)

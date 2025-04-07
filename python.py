from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import bcrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey'
USER_DB = 'users.db'
WINS_DB = 'wins.db'

# --- Helpers ---
def init_user_db():
    with sqlite3.connect(USER_DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password_hash BLOB,
                        is_admin INTEGER DEFAULT 0
                    )''')
        conn.commit()

def init_wins_db():
    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS wins (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        title TEXT,
                        description TEXT,
                        image TEXT,
                        auction_date TEXT,
                        final_bid REAL
                    )''')
        conn.commit()

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('username') == 'admin':
            return redirect(url_for('admin_panel'))
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        is_admin = 1 if username.lower() == 'admin' else 0
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
        try:
            with sqlite3.connect(USER_DB) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                          (username, password_hash, is_admin))
                conn.commit()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return 'Username already exists', 400
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')
    with sqlite3.connect(USER_DB) as conn:
        c = conn.cursor()
        c.execute('SELECT id, password_hash, is_admin FROM users WHERE username=?', (username,))
        user = c.fetchone()
        if user and bcrypt.checkpw(password, user[1]):
            session['user_id'] = user[0]
            session['username'] = username
            session['is_admin'] = bool(user[2])
            if username == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
    return 'Invalid credentials', 401

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or 'username' not in session:
        return redirect(url_for('index'))
    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()
        c.execute('SELECT title, description, image, auction_date, final_bid FROM wins WHERE username=?',
                  (session['username'],))
        auctions = c.fetchall()
    return render_template('dashboard.html', auctions=auctions)

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if session.get('username') != 'admin':
        return redirect(url_for('index'))
    with sqlite3.connect(USER_DB) as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE username != "admin"')
        users = [row[0] for row in c.fetchall()]

    if request.method == 'POST':
        username = request.form['username']
        title = request.form['title']
        description = request.form['description']
        image = request.form['image']
        auction_date = request.form['auction_date']
        final_bid = float(request.form['final_bid'])
        with sqlite3.connect(WINS_DB) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO wins (username, title, description, image, auction_date, final_bid)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (username, title, description, image, auction_date, final_bid))
            conn.commit()
        return redirect(url_for('admin_panel'))

    return render_template('admin_panel.html', users=users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    if not os.path.exists(USER_DB):
        init_user_db()
    if not os.path.exists(WINS_DB):
        init_wins_db()
    app.run(host='0.0.0.0', port=10000, debug=True)


#testing git imp
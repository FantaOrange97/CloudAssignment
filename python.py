from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import bcrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey'

USER_DB = 'users.db'
WINS_DB = 'wins.db'

# Create users table if it doesn't exist
def init_user_db():
    with sqlite3.connect(USER_DB) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash BLOB,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

# Create wins table if it doesn't exist
def init_wins_db():
    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS wins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                title TEXT,
                description TEXT,
                image TEXT,
                auction_date TEXT,
                final_bid REAL
            )
        ''')
        conn.commit()

# Landing page
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('username') == 'admin':
            return redirect(url_for('admin_panel'))
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form input
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Check if the user is admin
        is_admin = 1 if username.lower() == 'admin' else 0

        # Hash the password
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt())

        # Insert new user
        try:
            with sqlite3.connect(USER_DB) as conn:
                c = conn.cursor()
                c.execute('''
                    INSERT INTO users (username, password_hash, is_admin)
                    VALUES (?, ?, ?)
                ''', (username, password_hash, is_admin))
                conn.commit()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return 'Username already exists', 400

    return render_template('register.html')

# Handle user login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    with sqlite3.connect(USER_DB) as conn:
        c = conn.cursor()
        c.execute('SELECT id, password_hash, is_admin FROM users WHERE username=?', (username,))
        user = c.fetchone()

        # Validate user credentials
        if user and bcrypt.checkpw(password, user[1]):
            session['user_id'] = user[0]
            session['username'] = username
            session['is_admin'] = bool(user[2])
            if username == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))

    return 'Invalid credentials', 401

# User dashboard - show their wins
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or 'username' not in session:
        return redirect(url_for('index'))

    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT title, description, image, auction_date, final_bid
            FROM wins WHERE username=?
        ''', (session['username'],))
        auctions = c.fetchall()

    return render_template('dashboard.html', auctions=auctions)

# Admin panel - view all wins and add new ones
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if session.get('username') != 'admin':
        return redirect(url_for('index'))

    # Get list of non-admin users
    with sqlite3.connect(USER_DB) as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE username != "admin"')
        users = [row[0] for row in c.fetchall()]

    # Handle new win submission
    if request.method == 'POST':
        username = request.form['username']
        title = request.form['title']
        description = request.form['description']
        image = request.form['image']
        auction_date = request.form['auction_date']
        final_bid = float(request.form['final_bid'])

        with sqlite3.connect(WINS_DB) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO wins (username, title, description, image, auction_date, final_bid)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, title, description, image, auction_date, final_bid))
            conn.commit()

        return redirect(url_for('admin_panel'))

    # Get all wins
    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM wins')
        wins = c.fetchall()

    return render_template('admin_panel.html', users=users, wins=wins)

# Admin - edit existing win
@app.route('/admin/edit/<int:win_id>', methods=['GET', 'POST'])
def edit_win(win_id):
    if session.get('username') != 'admin':
        return redirect(url_for('index'))

    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()

        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            image = request.form['image']
            auction_date = request.form['auction_date']
            final_bid = float(request.form['final_bid'])

            # Update win data
            c.execute('''
                UPDATE wins
                SET title=?, description=?, image=?, auction_date=?, final_bid=?
                WHERE id=?
            ''', (title, description, image, auction_date, final_bid, win_id))
            conn.commit()
            return redirect(url_for('admin_panel'))

        # Get current win data
        c.execute('SELECT * FROM wins WHERE id=?', (win_id,))
        win = c.fetchone()

        if not win:
            return 'Win not found', 404

    return render_template('edit_win.html', win=win)

# Admin - delete a win
@app.route('/admin/delete/<int:win_id>', methods=['POST'])
def delete_win(win_id):
    if session.get('username') != 'admin':
        return redirect(url_for('index'))

    with sqlite3.connect(WINS_DB) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM wins WHERE id=?', (win_id,))
        conn.commit()

    return redirect(url_for('admin_panel'))

# Log out the current user
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Run the app
if __name__ == '__main__':
    if not os.path.exists(USER_DB):
        init_user_db()
    if not os.path.exists(WINS_DB):
        init_wins_db()
    app.run(host='0.0.0.0', port=10000, debug=True)
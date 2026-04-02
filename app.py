import os
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import sqlite3
import threading
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from detector import start_sniffing, init_db, get_stats, toggle_sniffing, get_sniffing_status, get_recent_traffic, get_recent_dns

app = Flask(__name__)
# Secure random key for session
app.secret_key = os.urandom(24)
DB_FILE = "alerts.db"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            conn = sqlite3.connect(DB_FILE, timeout=5)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error="Invalid credentials")
        except Exception as e:
            return render_template('login.html', error="Database error")

    registered = request.args.get('registered')
    return render_template('login.html', registered=registered)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('register.html', error="Username and password are required")
            
        try:
            conn = sqlite3.connect(DB_FILE, timeout=5)
            c = conn.cursor()
            
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            if c.fetchone():
                conn.close()
                return render_template('register.html', error="Username already exists")
                
            hashed_pw = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            
            return redirect(url_for('login', registered=True))
        except Exception as e:
            return render_template('register.html', error="Database error")

    return render_template('register.html')

@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/alerts")
@login_required
def get_alerts():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Fetch the latest 50 alerts
        c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
        rows = c.fetchall()
        conn.close()
        
        alerts = [dict(ix) for ix in rows]
        return jsonify(alerts)
    except Exception as e:
        return jsonify([])

@app.route("/api/stats")
@login_required
def api_stats():
    stats = get_stats()
    
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        c = conn.cursor()
        c.execute("SELECT count(*) FROM alerts")
        stats['total_alerts'] = c.fetchone()[0]
        conn.close()
    except:
        stats['total_alerts'] = 0
        
    stats['sniffing_active'] = get_sniffing_status()
    return jsonify(stats)

@app.route("/api/traffic")
@login_required
def api_traffic():
    return jsonify(get_recent_traffic())

@app.route("/api/dns")
@login_required
def api_dns():
    return jsonify(get_recent_dns())

@app.route("/api/risk-summary")
@login_required
def api_risk_summary():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        c = conn.cursor()
        c.execute("SELECT risk_level, count(*) as c FROM alerts GROUP BY risk_level")
        rows = c.fetchall()
        conn.close()
        
        summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for row in rows:
            if row[0] in summary:
                summary[row[0]] = row[1]
        return jsonify(summary)
    except Exception as e:
        return jsonify({"LOW": 0, "MEDIUM": 0, "HIGH": 0})

@app.route("/api/alerts/summary")
@login_required
def api_alerts_summary():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        c = conn.cursor()
        c.execute("SELECT rule, count(*) as c FROM alerts GROUP BY rule")
        rows = c.fetchall()
        conn.close()
        
        summary = {"Port Scan": 0, "SYN Flood": 0, "ICMP Flood": 0}
        for row in rows:
            summary[row[0]] = row[1]
        return jsonify(summary)
    except Exception as e:
        return jsonify({"Port Scan": 0, "SYN Flood": 0, "ICMP Flood": 0})

@app.route("/api/toggle", methods=['POST'])
@login_required
def api_toggle():
    data = request.get_json() or {}
    new_state = data.get("active")
    if new_state is not None:
        toggle_sniffing(new_state)
    return jsonify({"sniffing_active": get_sniffing_status()})

@app.route("/api/alerts/clear", methods=['POST'])
@login_required
def api_alerts_clear():
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        c = conn.cursor()
        c.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    init_db()
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)

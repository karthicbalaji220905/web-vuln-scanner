from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
import os
import time
from scanner import full_scan

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Default login credentials (change these!)
USERNAME = "admin"
PASSWORD = "admin123"

# ─── Login Required Decorator ───────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─── Login Page ─────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == USERNAME and password == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password. Please try again.'
    return render_template('login.html', error=error)

# ─── Logout ─────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Main Scanner Page ───────────────────────────────────────
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# ─── Scan Route ─────────────────────────────────────────────
@app.route('/scan', methods=['POST'])
@login_required
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'})

    if not url.startswith('http'):
        url = 'https://' + url

    try:
        results = full_scan(url)
        report_path = f'reports/scan_{int(time.time())}.json'
        os.makedirs('reports', exist_ok=True)
        with open(report_path, 'w') as f:
            import json
            json.dump(results, f, indent=2)

        return jsonify({
            'success': True,
            'results': results,
            'report_path': report_path
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ─── Download Report ─────────────────────────────────────────
@app.route('/reports/<path:filename>')
@login_required
def download_report(filename):
    return send_from_directory('reports', filename, as_attachment=True)

if __name__ == '__main__':
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)

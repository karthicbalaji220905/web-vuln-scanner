from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import time
from scanner import full_scan

app = Flask(_name_)
app.secret_key = 'supersecretkey'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'})
    
    if not url.startswith('http'):
        url = 'https://' + url
    
    try:
        results = full_scan(url)
        
        # Save report
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

@app.route('/reports/<path:filename>')
def download_report(filename):
    return send_from_directory('reports', filename, as_attachment=True)

if _name_ == '_main_':
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)

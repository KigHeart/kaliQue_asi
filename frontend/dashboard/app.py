from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Path to CLI binary
CLI_PATH = Path(__file__).parent.parent.parent / "cli" / "target" / "release" / "kalique.exe"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/test', methods=['POST'])
def test_pqc():
    """Test PQC operations"""
    data = request.json
    test_type = data.get('test_type', 'all')
    
    try:
        result = subprocess.run(
            [str(CLI_PATH), 'test', '--test-type', test_type],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout if result.stdout else result.stderr,
            'error': result.stderr if result.returncode != 0 else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    """Analyze codebase for crypto usage"""
    data = request.json
    path = data.get('path', '.')
    
    try:
        result = subprocess.run(
            [str(CLI_PATH), 'analyze', '--path', path, '--format', 'summary'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout if result.stdout else 'No output',
            'error': result.stderr if result.returncode != 0 else None
        })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/keygen', methods=['POST'])
def generate_keys():
    """Generate PQC keys"""
    data = request.json
    algorithm = data.get('algorithm', 'kyber')
    key_id = data.get('key_id', 'default_key')
    output_dir = data.get('output', './keys')
    
    try:
        result = subprocess.run(
            [str(CLI_PATH), 'keygen', 
             '--algorithm', algorithm,
             '--id', key_id,
             '--output', output_dir],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout if result.stdout else result.stderr,
            'error': result.stderr if result.returncode != 0 else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        'status': 'online',
        'cli_available': CLI_PATH.exists(),
        'version': '0.1.0'
    })

if __name__ == '__main__':
    print("🔐 kaliQue_asi Dashboard Server")
    print(f"CLI Path: {CLI_PATH}")
    print(f"CLI Exists: {CLI_PATH.exists()}")
    print("\nStarting server on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

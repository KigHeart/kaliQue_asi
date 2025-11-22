from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import subprocess
import json
import os
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Path to CLI binary
CLI_PATH = Path(__file__).parent.parent.parent / "cli" / "target" / "release" / "kalique.exe"
KEYS_DIR = Path(__file__).parent.parent.parent / "keys"

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
    output_dir = data.get('output', str(KEYS_DIR))
    
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

@app.route('/api/keys', methods=['GET'])
def list_keys():
    """List all generated keys"""
    try:
        if not KEYS_DIR.exists():
            return jsonify({'keys': []})
        
        keys = []
        key_files = {}
        
        # Group keys by ID
        for file in KEYS_DIR.glob('*.key'):
            parts = file.stem.rsplit('_', 1)
            if len(parts) == 2:
                key_id, key_type = parts
                if key_id not in key_files:
                    key_files[key_id] = {}
                key_files[key_id][key_type] = {
                    'path': str(file),
                    'size': file.stat().st_size,
                    'modified': datetime.fromtimestamp(file.stat().st_mtime).isoformat()
                }
        
        # Format for display
        for key_id, files in key_files.items():
            keys.append({
                'id': key_id,
                'public': files.get('public'),
                'secret': files.get('secret'),
                'has_both': 'public' in files and 'secret' in files
            })
        
        return jsonify({'keys': keys})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/<key_id>', methods=['DELETE'])
def delete_key(key_id):
    """Delete a key pair"""
    try:
        deleted = []
        for key_type in ['public', 'secret']:
            key_file = KEYS_DIR / f"{key_id}_{key_type}.key"
            if key_file.exists():
                key_file.unlink()
                deleted.append(key_type)
        
        return jsonify({
            'success': len(deleted) > 0,
            'deleted': deleted
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/plan', methods=['POST'])
def generate_plan():
    """Generate migration plan"""
    data = request.json
    report_path = data.get('report_path', './analysis_report.md')
    strategy = data.get('strategy', 'hybrid')
    output_path = data.get('output_path', './migration_plan.md')
    
    try:
        result = subprocess.run(
            [str(CLI_PATH), 'plan',
             '--report', report_path,
             '--strategy', strategy,
             '--output', output_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        return jsonify({
            'success': result.returncode == 0,
            'output': result.stdout if result.stdout else result.stderr,
            'plan_path': output_path if result.returncode == 0 else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        'status': 'online',
        'cli_available': CLI_PATH.exists(),
        'version': '0.1.0',
        'keys_directory': str(KEYS_DIR)
    })

if __name__ == '__main__':
    print("🔐 kaliQue_asi Dashboard Server")
    print(f"CLI Path: {CLI_PATH}")
    print(f"CLI Exists: {CLI_PATH.exists()}")
    print(f"Keys Directory: {KEYS_DIR}")
    print("\nStarting server on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

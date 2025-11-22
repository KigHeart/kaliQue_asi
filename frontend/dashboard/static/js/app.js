// API Base URL
const API_BASE = 'http://localhost:5000/api';

// Statistics
let stats = {
    testsRun: 0,
    keysGenerated: 0,
    filesAnalyzed: 0,
    plansCreated: 0
};

// Check system status on load
window.addEventListener('DOMContentLoaded', async () => {
    await checkStatus();
    updateStats();
});

async function checkStatus() {
    try {
        const response = await fetch(`${API_BASE}/status`);
        const data = await response.json();
        
        const statusEl = document.getElementById('status-text');
        if (data.status === 'online' && data.cli_available) {
            statusEl.textContent = 'System Online';
            statusEl.style.color = '#4caf50';
        } else {
            statusEl.textContent = 'CLI Not Available';
            statusEl.style.color = '#f44336';
        }
    } catch (error) {
        document.getElementById('status-text').textContent = 'Server Offline';
        document.getElementById('status-text').style.color = '#f44336';
    }
}

async function testPQC(testType) {
    const outputEl = document.getElementById('test-output');
    outputEl.textContent = 'Running tests...';
    outputEl.className = 'output show';
    
    try {
        const response = await fetch(`${API_BASE}/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ test_type: testType })
        });
        
        const data = await response.json();
        
        if (data.success) {
            outputEl.textContent = data.output;
            outputEl.className = 'output show success';
            stats.testsRun++;
            updateStats();
        } else {
            outputEl.textContent = `Error: ${data.error}`;
            outputEl.className = 'output show error';
        }
    } catch (error) {
        outputEl.textContent = `Error: ${error.message}`;
        outputEl.className = 'output show error';
    }
}

async function analyzeCode() {
    const path = document.getElementById('analyze-path').value;
    const outputEl = document.getElementById('analyze-output');
    
    outputEl.textContent = 'Analyzing codebase...';
    outputEl.className = 'output show';
    
    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        
        const data = await response.json();
        
        if (data.success) {
            outputEl.textContent = data.output;
            outputEl.className = 'output show success';
            stats.filesAnalyzed++;
            updateStats();
        } else {
            outputEl.textContent = `Error: ${data.error}`;
            outputEl.className = 'output show error';
        }
    } catch (error) {
        outputEl.textContent = `Error: ${error.message}`;
        outputEl.className = 'output show error';
    }
}

async function generateKeys() {
    const algorithm = document.getElementById('keygen-algorithm').value;
    const keyId = document.getElementById('keygen-id').value;
    const output = document.getElementById('keygen-output').value;
    const outputEl = document.getElementById('keygen-output-display');
    
    outputEl.textContent = 'Generating keys...';
    outputEl.className = 'output show';
    
    try {
        const response = await fetch(`${API_BASE}/keygen`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algorithm, key_id: keyId, output })
        });
        
        const data = await response.json();
        
        if (data.success) {
            outputEl.textContent = data.output;
            outputEl.className = 'output show success';
            stats.keysGenerated++;
            updateStats();
            // Auto-refresh keys list
            setTimeout(loadKeys, 1000);
        } else {
            outputEl.textContent = `Error: ${data.error}`;
            outputEl.className = 'output show error';
        }
    } catch (error) {
        outputEl.textContent = `Error: ${error.message}`;
        outputEl.className = 'output show error';
    }
}

async function loadKeys() {
    const keysListEl = document.getElementById('keys-list');
    keysListEl.innerHTML = '<p class="loading-text">Loading keys...</p>';
    
    try {
        const response = await fetch(`${API_BASE}/keys`);
        const data = await response.json();
        
        if (data.keys && data.keys.length > 0) {
            let html = '<div class="keys-grid">';
            
            for (const key of data.keys) {
                const pubSize = key.public ? (key.public.size / 1024).toFixed(2) : 'N/A';
                const secSize = key.secret ? (key.secret.size / 1024).toFixed(2) : 'N/A';
                const modified = key.public ? new Date(key.public.modified).toLocaleString() : 'N/A';
                
                html += `
                    <div class="key-card">
                        <div class="key-header">
                            <h3>🔑 ${key.id}</h3>
                            <button onclick="deleteKey('${key.id}')" class="btn-delete">🗑️</button>
                        </div>
                        <div class="key-info">
                            <div class="key-detail">
                                <span class="label">Public Key:</span>
                                <span class="value">${pubSize} KB</span>
                            </div>
                            <div class="key-detail">
                                <span class="label">Secret Key:</span>
                                <span class="value">${secSize} KB</span>
                            </div>
                            <div class="key-detail">
                                <span class="label">Modified:</span>
                                <span class="value">${modified}</span>
                            </div>
                            <div class="key-status ${key.has_both ? 'complete' : 'incomplete'}">
                                ${key.has_both ? '✓ Complete' : '⚠ Incomplete'}
                            </div>
                        </div>
                    </div>
                `;
            }
            
            html += '</div>';
            keysListEl.innerHTML = html;
        } else {
            keysListEl.innerHTML = '<p class="no-keys">No keys found. Generate some keys to get started!</p>';
        }
    } catch (error) {
        keysListEl.innerHTML = `<p class="error-text">Error loading keys: ${error.message}</p>`;
    }
}

async function deleteKey(keyId) {
    if (!confirm(`Are you sure you want to delete key pair "${keyId}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/keys/${keyId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`Successfully deleted ${data.deleted.join(' and ')} key(s)`);
            loadKeys();
        } else {
            alert(`Error: ${data.error}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

async function generatePlan() {
    const reportPath = document.getElementById('plan-report').value;
    const strategy = document.getElementById('plan-strategy').value;
    const outputPath = document.getElementById('plan-output').value;
    const outputEl = document.getElementById('plan-output');
    
    outputEl.textContent = 'Generating migration plan...';
    outputEl.className = 'output show';
    
    try {
        const response = await fetch(`${API_BASE}/plan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                report_path: reportPath,
                strategy: strategy,
                output_path: outputPath
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            outputEl.textContent = data.output + `\n\nPlan saved to: ${data.plan_path}`;
            outputEl.className = 'output show success';
            stats.plansCreated++;
            updateStats();
        } else {
            outputEl.textContent = `Error: ${data.error || 'Failed to generate plan'}`;
            outputEl.className = 'output show error';
        }
    } catch (error) {
        outputEl.textContent = `Error: ${error.message}`;
        outputEl.className = 'output show error';
    }
}

function updateStats() {
    const statsGrid = document.querySelectorAll('.stat-value');
    statsGrid[0].textContent = stats.testsRun;
    statsGrid[1].textContent = stats.keysGenerated;
    statsGrid[2].textContent = stats.filesAnalyzed;
    if (statsGrid[3]) {
        statsGrid[3].textContent = stats.plansCreated;
    }
}

// API Base URL
const API_BASE = 'http://localhost:5000/api';

// Statistics
let stats = {
    testsRun: 0,
    keysGenerated: 0,
    filesAnalyzed: 0
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
            outputEl.textContent = data.raw_output;
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
        } else {
            outputEl.textContent = `Error: ${data.error}`;
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
}

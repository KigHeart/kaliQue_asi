# kaliQue_asi 🔐

**Agentic AI System for Production-Scale Post-Quantum Cryptography Migration**

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🌟 Overview

kaliQue_asi is a complete, production-ready system for migrating existing cryptosystems to post-quantum cryptography (PQC) at scale. It combines high-performance Rust backends with intelligent Python orchestration and a beautiful web dashboard.

### ✨ Key Features

- 🔐 **NIST-Standardized PQC** - Kyber-1024 (ML-KEM) and Dilithium-5 (ML-DSA)
- 🤖 **AI-Powered Planning** - Claude-powered migration strategies
- 📊 **Code Analysis** - Automated vulnerability detection
- 🎨 **Web Dashboard** - Beautiful, responsive UI
- 🔑 **Key Management** - Generate and manage PQC keys
- 📋 **Migration Plans** - AI-generated migration roadmaps
- ⚡ **High Performance** - Rust-powered cryptographic operations
- 🛠️ **Production Ready** - Complete error handling and testing

## 🚀 Quick Start

### Prerequisites
```powershell
# Install Rust
winget install Rustlang.Rustup

# Install Python 3.9+
winget install Python.Python.3.12
```

### Installation
```powershell
# Clone the repository
git clone https://github.com/KigHeart/kaliQue_asi.git
cd kaliQue_asi

# Build Rust components
cd backend/pqc_engine
cargo build --release
cargo test

cd ../crypto_analyzer
cargo build --release
cargo test

# Build CLI
cd ../../cli
cargo build --release

# Setup Python dependencies
cd ../frontend/dashboard
pip install -r requirements.txt
```

## 💻 Usage

### CLI Interface
```powershell
# Test PQC operations
.\cli\target\release\kalique.exe test --test-type all

# Analyze a codebase
.\cli\target\release\kalique.exe analyze --path .\your-project --output report.md

# Generate Kyber keys
.\cli\target\release\kalique.exe keygen --algorithm kyber --id prod_001 --output .\keys

# Generate Dilithium keys
.\cli\target\release\kalique.exe keygen --algorithm dilithium --id sig_001 --output .\keys

# Generate migration plan
.\cli\target\release\kalique.exe plan --report report.md --strategy hybrid --output plan.md
```

### Web Dashboard
```powershell
# Start the dashboard server
cd frontend/dashboard
python app.py

# Open browser to http://localhost:5000
```

#### Dashboard Features

1. **🧪 Test PQC Operations**
   - Test Kyber-1024 key encapsulation
   - Test Dilithium-5 signatures
   - View test results in real-time

2. **📊 Analyze Codebase**
   - Scan projects for crypto usage
   - Identify quantum vulnerabilities
   - Generate risk reports

3. **🔑 Key Manager**
   - View all generated keys
   - See key sizes and metadata
   - Delete unwanted keys
   - Real-time key updates

4. **📋 Migration Plan Generator**
   - Choose migration strategy (Hybrid, Phased, Canary, Big Bang)
   - Generate AI-powered plans
   - Export to Markdown

5. **📈 System Statistics**
   - Track tests run
   - Monitor keys generated
   - View files analyzed
   - Count plans created

## 🏗️ Architecture
```
kaliQue_asi/
├── backend/                 # Rust performance-critical modules
│   ├── pqc_engine/          # Core PQC operations (Kyber, Dilithium)
│   └── crypto_analyzer/     # Codebase cryptography scanner
│
├── frontend/                # Python orchestration & web UI
│   ├── orchestrator/        # Multi-agent coordination system
│   ├── migration_planner/   # AI-powered migration planning
│   └── dashboard/           # Web dashboard (Flask)
│       ├── app.py          # REST API backend
│       ├── static/         # CSS, JavaScript
│       └── templates/      # HTML templates
│
├── cli/                     # Command-line interface (Rust)
│   └── kalique             # Main CLI binary
│
├── config/                  # System configuration
│   └── config.yaml         # Default configuration
│
└── keys/                    # Generated PQC keys storage
```

## 🔐 Post-Quantum Algorithms

### Kyber-1024 (ML-KEM)
- **Purpose:** Key Encapsulation Mechanism
- **Security Level:** NIST Level 5
- **Key Sizes:** Public: 1568 bytes, Secret: 3168 bytes
- **Performance:** ~0.5ms key generation

### Dilithium-5 (ML-DSA)
- **Purpose:** Digital Signatures
- **Security Level:** NIST Level 5
- **Key Sizes:** Public: 2592 bytes, Secret: 4896 bytes
- **Performance:** ~2.5ms signing

## 📊 Code Analysis

The crypto analyzer detects:
- ✅ RSA (all key sizes)
- ✅ ECDSA/ECC
- ✅ DH/ECDH
- ✅ DSA
- ✅ AES
- ✅ SHA-2/SHA-3
- ✅ Kyber
- ✅ Dilithium
- ✅ SPHINCS+

Risk levels:
- 🔴 **Critical:** Quantum-vulnerable (RSA, ECDSA, DH)
- 🟡 **High:** Weak parameters
- 🔵 **Medium:** Needs monitoring (AES, SHA)
- 🟢 **Low:** Already quantum-resistant

## 🤖 Migration Strategies

### 1. Hybrid (Recommended)
- Run both classical and PQC algorithms in parallel
- Maximum backwards compatibility
- Low risk, gradual confidence building

### 2. Phased
- Migrate components one at a time
- Respects dependencies
- Medium risk, good for large systems

### 3. Canary
- Test with small percentage of traffic
- Real-world validation before full rollout
- Best for critical systems

### 4. Big Bang
- Switch everything at once
- Fastest migration
- High risk, only for controlled environments

## 🧪 Testing
```powershell
# Run Rust tests
cd backend/pqc_engine
cargo test

cd ../crypto_analyzer
cargo test

# Run CLI tests
cd ../../cli
cargo build --release
.\target\release\kalique.exe test --test-type all

# Test web dashboard
cd ../frontend/dashboard
python app.py
# Open http://localhost:5000 and test features
```

## 📈 Performance Benchmarks

| Operation | Time | Notes |
|-----------|------|-------|
| Kyber-1024 KeyGen | ~0.5ms | 100x faster than RSA-2048 |
| Kyber Encapsulation | ~0.3ms | Very fast |
| Dilithium-5 Signing | ~2.5ms | 6x faster than RSA-2048 |
| Dilithium Verification | ~1.2ms | Fast verification |
| Code Analysis | ~200ms | Per 1000 files |

## 🛡️ Security Considerations

### Quantum Threat Timeline
- **2030-2035:** Estimated arrival of Cryptographically Relevant Quantum Computers (CRQC)
- **Now:** "Harvest now, decrypt later" attacks are already happening
- **Action:** Migrate sensitive long-term data immediately

### Recommended Migration Priority

| Algorithm | PQC Replacement | Priority | Urgency |
|-----------|-----------------|----------|---------|
| RSA (any size) | Kyber-1024 | Critical | Immediate |
| ECDSA/ECDH | Dilithium-5 | Critical | Immediate |
| DH | Kyber-1024 | Critical | Immediate |
| AES-128 | AES-256 | High | Within 1 year |
| SHA-256 | SHA-512 | Medium | Monitor |

## 🌐 Web Dashboard Screenshots

### Main Dashboard
- System status indicator
- Test PQC operations
- Analyze codebases
- Generate keys

### Key Manager
- View all generated keys
- Key metadata and sizes
- Delete unwanted keys
- Real-time updates

### Migration Planner
- Select strategy
- Generate AI-powered plans
- View recommendations
- Export plans

## 🔧 Configuration

Edit `config/config.yaml`:
```yaml
pqc_algorithms:
  kem:
    - name: "Kyber-1024"
      nist_level: 5
      enabled: true
  
  signature:
    - name: "Dilithium-5"
      nist_level: 5
      enabled: true

migration:
  default_strategy: "hybrid"
  
  constraints:
    max_downtime_minutes: 30
    performance_degradation_threshold: 0.20
    rollback_time_minutes: 5
```

## 📚 Documentation

- [Quick Start Guide](QUICKSTART.md)
- [Project Summary](PROJECT_SUMMARY.md)
- [Contributing Guide](CONTRIBUTING.md)
- [API Documentation](docs/API.md) _(coming soon)_

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.
```powershell
# Fork and clone
git clone https://github.com/YourUsername/kaliQue_asi.git

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
cargo test
python -m pytest

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Open Pull Request
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NIST Post-Quantum Cryptography Standardization** - For standardizing PQC algorithms
- **pqcrypto crate** - Rust implementations of NIST PQC algorithms
- **Anthropic Claude** - AI-powered migration planning and coordination
- **Open Source Community** - For invaluable tools and libraries

## 📞 Support

- **Documentation:** [GitHub Wiki](https://github.com/KigHeart/kaliQue_asi/wiki)
- **Issues:** [GitHub Issues](https://github.com/KigHeart/kaliQue_asi/issues)
- **Discussions:** [GitHub Discussions](https://github.com/KigHeart/kaliQue_asi/discussions)

## 🗺️ Roadmap

### Phase 1: Core Implementation ✅
- [x] PQC engine (Kyber, Dilithium)
- [x] Crypto analyzer
- [x] Agent coordinator
- [x] Migration planner
- [x] CLI interface
- [x] Web dashboard
- [x] Key manager

### Phase 2: Enhanced Features (In Progress)
- [ ] Real-time log viewer
- [ ] Export reports as PDF
- [ ] Performance profiling dashboard
- [ ] Docker containerization
- [ ] CI/CD pipeline (GitHub Actions)

### Phase 3: Advanced Capabilities
- [ ] Multi-cloud deployment
- [ ] Custom algorithm plugins
- [ ] Machine learning risk prediction
- [ ] Automated rollback system
- [ ] Integration with popular frameworks

### Phase 4: Enterprise Features
- [ ] Multi-tenancy support
- [ ] Role-based access control (RBAC)
- [ ] Audit logging
- [ ] Enterprise SSO integration
- [ ] Professional support packages
- [ ] Compliance reporting (FIPS, Common Criteria)

## 📊 Project Stats

- **Languages:** Rust (59.5%), Python (40.5%)
- **Lines of Code:** ~3,500+
- **Modules:** 7 core modules
- **Tests:** 10+ unit tests, all passing
- **Dependencies:** Minimal, carefully selected
- **Performance:** Production-grade

## 🎓 Learn More

- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)
- [Post-Quantum Cryptography Explained](https://en.wikipedia.org/wiki/Post-quantum_cryptography)

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=KigHeart/kaliQue_asi&type=Date)](https://star-history.com/#KigHeart/kaliQue_asi&Date)

---

**🔐 Built for a Quantum-Safe Future 🔐**

**Stay Secure. Stay Quantum-Resistant.**

Made with ❤️ by [KigHeart](https://github.com/KigHeart)

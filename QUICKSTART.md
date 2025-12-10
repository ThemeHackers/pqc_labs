# Quantum Shield PQC Labs - Quick Start Guide

## 🚀 Quick Installation

### Prerequisites
- Python 3.8 or higher
- `pip` package manager

### Setup in 3 Steps

1. **Clone and Navigate**
   ```bash
   git clone <your-repository-url>
   cd pqc_labs
   ```

2. **Install Dependencies**
   ```bash
   # Optional: Create virtual environment
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install required packages
   pip install -r requirements.txt
   ```

3. **Start the Server**
   ```bash
   uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```

## 🌐 Access the Application

- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Alternative API Docs**: http://localhost:8000/redoc

## 🧪 Verify Installation

Run the test suite to ensure everything works:

```bash
# Using pytest (recommended)
pytest test_app.py -v

# Or run directly
python3 test_app.py
```

Expected output: `Test Results: 10/10 passed` or `10 passed` with pytest

## 📚 Key Features Overview

### Post-Quantum Cryptography
- **ML-KEM-512 (Kyber)**: Quantum-resistant key exchange
- **ML-DSA-44 (Dilithium)**: Post-quantum digital signatures
- **Hybrid Encryption**: AES-256-GCM + Kyber for file sharing

### Interactive Labs
- Hash functions (SHA-256, SHA-512, SHA3-256, MD5)
- AES encryption/decryption
- HMAC authentication
- Password strength analysis (Classical vs Quantum)
- Zero-Knowledge Proofs
- Merkle Trees
- Lattice-based cryptography (LWE)
- Quantum algorithms (Grover, Shor)
- QKD (BB84 protocol)

### Security & Monitoring
- Encrypted vault storage
- Audit logging
- Access policy controls
- System health monitoring
- Network traffic analysis

## 🔑 Quick API Examples

### 1. Kyber Key Exchange
```bash
curl -X POST http://localhost:8000/api/kem/exchange
```

### 2. Generate Digital Identity
```bash
curl -X POST http://localhost:8000/api/sign/keys
```

### 3. Hash Text
```bash
curl -X POST http://localhost:8000/api/lab/hash \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello PQC!", "algo": "sha256"}'
```

### 4. Check System Health
```bash
curl http://localhost:8000/api/health
```

## 🛡️ Security Policies

The application includes configurable security policies:
- PQC Handshake enforcement
- Legacy algorithm blocking
- TLS version requirements
- Entropy validation

Access policies can be toggled via the web UI or API.

## 📖 Learn More

- Explore the interactive UI for hands-on demonstrations
- Check `/docs` for complete API reference
- Read `README.md` for detailed feature documentation

## 🐛 Troubleshooting

**Module not found errors?**
```bash
pip install -r requirements.txt
```

**Port already in use?**
```bash
uvicorn app:app --port 8080  # Use a different port
```

**Permission errors on Linux?**
```bash
# Entropy reading requires /dev/urandom access (usually available by default)
# Health monitoring requires psutil (included in requirements.txt)
```

## 🎓 Educational Use

This application is designed for:
- Learning post-quantum cryptography concepts
- Understanding classical vs quantum security
- Experimenting with cryptographic primitives
- Exploring quantum algorithms
- Demonstrating security best practices

**Note**: This is an educational platform. For production use, always review and adapt security configurations to your specific requirements.

---

**Happy Learning! 🔐🔬**

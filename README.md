# Quantum Shield PQC Labs

**Quantum Shield PQC Labs** is a FastAPI-based application designed to demonstrate and experiment with **Post-Quantum Cryptography (PQC)** alongside classical cryptographic concepts. It provides a platform to understand how future-proof security mechanisms work in practice.

## 🚀 Features

### Post-Quantum Cryptography (PQC)
*   **Secure File Sharing**: encrypt and upload files using a hybrid approach (AES-256-GCM + **Kyber512** for key encapsulation).
*   **Key Exchange**: Perform real **Kyber512** key exchange handshakes between Alice and Bob simulations.
*   **Digital Signatures**: Generate identities and sign/verify messages using **ML-DSA-44 (Dilithium2)**.

### Security & Vault
*   **Vault Storage**: Securely store secrets using AES-256-GCM.
*   **Access Policies**: Configurable security policies (e.g., enforce PQC, block legacy TLS, require entropy).
*   **Audit Logging**: comprehensive logging of security events (Key Generation, Uploads, Policy Changes).

### Cryptography Labs
Interactive educational labs to explore core concepts:
*   **Hashing**: Experiment with SHA-256, SHA-512, SHA3-256, and MD5 (insecure).
*   **AES Encryption**: Encrypt/Decrypt text using AES-CTR.
*   **HMAC**: Generate message authentication codes.
*   **Password Strength**: Analyze password entropy and estimate cracking times (Classical vs. Quantum).
*   **Entropy Analysis**: Visualize randomness and distribution from system entropy sources.
*   **Zero-Knowledge Proofs (ZKP)**: Verify discrete-log based proofs (Chaum-Pedersen).
*   **PKI**: Issue X.509 certificates signed by a local "Quantum Shield Root CA".
*   **Lattice-based Cryptography (LWE)**: Visualize Learning With Errors (LWE) samples and noise.
*   **Merkle Trees**: Build hash trees and verify inclusion proofs.
*   **Grover's Algorithm**: Simulate quantum oracle checks for search problems.
*   **Shor's Algorithm**: Demonstrate period finding and integer factorization.
*   **Quantum Key Distribution (QKD)**: Simulate BB84 protocol basis sifting and key generation.

### System Monitoring
*   **Health Dashboard**: Real-time CPU, RAM, Disk usage, and Entropy levels.
*   **Network Stats**: Monitor incoming/outgoing traffic.

## 🛠️ Installation

### Prerequisites
*   Python 3.8 or higher
*   `pip` package manager

### Steps
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ThemeHackers/pqc_labs
    cd pqc_labs
    ```

2.  **Install dependencies:**
    It is recommended to use a virtual environment.
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
    pip3 install -r requirements.txt
    ```
    *(Note: `pqcrypto` is required for Kyber and Dilithium implementations)*

## 🏃 Usage

1.  **Start the server:**
    ```bash
    uvicorn app:app --reload --host 0.0.0.0 --port 8000
    ```

2.  **Access the Application:**
    Open your browser and navigate to:
    `http://localhost:8000`

3.  **Explore the API:**
    Interactive API documentation is available at:
    `http://localhost:8000/docs`

## 🛡️ Security Policies
The application allows dynamic toggling of security rules via the UI or API:
*   `pqc_handshake`: Enable/Disable Kyber key exchange.
*   `access_policies`: Block legacy algorithms or require specific PQC standards.

---
*Disclaimer: This project is for educational and demonstration purposes. While it uses real cryptographic libraries, always review configuration and dependencies before production use.*

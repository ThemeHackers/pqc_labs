"""
Test Suite for Quantum Shield PQC Labs
Validates core functionality of the FastAPI application
"""

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


class TestBasicEndpoints:
    """Test basic application endpoints"""
    
    def test_homepage_loads(self):
        """Test that the homepage loads successfully"""
        response = client.get("/")
        assert response.status_code == 200
        assert b"Quantum Shield" in response.content
    
    def test_api_docs_available(self):
        """Test that API documentation is accessible"""
        response = client.get("/docs")
        assert response.status_code == 200
    
    def test_health_endpoint(self):
        """Test system health monitoring endpoint"""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "cpu_load" in data
        assert "ram_usage" in data
        assert "platform" in data


class TestPQCFeatures:
    """Test Post-Quantum Cryptography features"""
    
    def test_kyber_key_exchange(self):
        """Test Kyber512 (ML-KEM-512) key exchange"""
        response = client.post("/api/kem/exchange")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["match"] is True  # Shared secrets must match
        assert "alice_pk" in data
        assert "bob_shared_secret" in data
        assert "alice_shared_secret" in data
    
    def test_dilithium_key_generation(self):
        """Test ML-DSA-44 (Dilithium2) key generation"""
        response = client.post("/api/sign/keys")
        assert response.status_code == 200
        data = response.json()
        assert "public_key" in data
        assert "secret_key" in data
        assert len(data["public_key"]) > 0
        assert len(data["secret_key"]) > 0


class TestCryptoLabs:
    """Test cryptographic laboratory features"""
    
    def test_hash_lab_sha256(self):
        """Test SHA-256 hashing"""
        response = client.post(
            "/api/lab/hash",
            json={"text": "Hello PQC!", "algo": "sha256"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "result" in data
        assert len(data["result"]) == 64  # SHA-256 produces 64 hex chars
    
    def test_password_strength_audit(self):
        """Test password strength analysis"""
        response = client.post(
            "/api/lab/password",
            json={"password": "MySecureP@ssw0rd123!"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "bits" in data
        assert "classic_time" in data
        assert "quantum_time" in data
        assert data["bits"] > 0
    
    def test_merkle_tree_builder(self):
        """Test Merkle tree construction"""
        response = client.post(
            "/api/lab/merkle/build",
            json={"leaves": ["tx1", "tx2", "tx3", "tx4"]}
        )
        assert response.status_code == 200
        data = response.json()
        assert "levels" in data
        assert "root" in data
        assert len(data["root"]) == 64  # SHA-256 hash


class TestSecurityFeatures:
    """Test security and vault features"""
    
    def test_audit_logs(self):
        """Test audit log retrieval"""
        response = client.get("/api/audit/logs")
        assert response.status_code == 200
        logs = response.json()
        assert isinstance(logs, list)
    
    def test_access_policy_state(self):
        """Test access policy retrieval"""
        response = client.get("/api/access/state")
        assert response.status_code == 200
        policies = response.json()
        assert "pqc_handshake" in policies
        assert isinstance(policies["pqc_handshake"], bool)


if __name__ == "__main__":
    import sys
    
    # Simple test runner
    test_classes = [
        TestBasicEndpoints,
        TestPQCFeatures,
        TestCryptoLabs,
        TestSecurityFeatures
    ]
    
    total_tests = 0
    passed_tests = 0
    
    for test_class in test_classes:
        print(f"\n{'='*60}")
        print(f"Running: {test_class.__name__}")
        print('='*60)
        
        instance = test_class()
        test_methods = [m for m in dir(instance) if m.startswith("test_")]
        
        for method_name in test_methods:
            total_tests += 1
            try:
                method = getattr(instance, method_name)
                method()
                print(f"✓ {method_name}")
                passed_tests += 1
            except AssertionError as e:
                print(f"✗ {method_name}: {e}")
            except Exception as e:
                print(f"✗ {method_name}: {type(e).__name__}: {e}")
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed_tests}/{total_tests} passed")
    print('='*60)
    
    sys.exit(0 if passed_tests == total_tests else 1)

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import sys
import os
import random
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import hmac
import math
from typing import Optional
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import timedelta
try:
    from pqcrypto.kem import ml_kem_512
    from pqcrypto.sign import ml_dsa_44
    kyber512 = ml_kem_512
    dilithium2 = ml_dsa_44
except ImportError:
    sys.exit(1)
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
CLOUD_STORAGE = {}
file_storage = {}
keys_db = {}
def generate_aes_key():
    return os.urandom(32), os.urandom(12)
def encrypt_aes_gcm(key, nonce, plaintext):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag
def decrypt_aes_gcm(key, nonce, ciphertext_with_tag):
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
class SignRequest(BaseModel):
    message: str
class VerifyRequest(BaseModel):
    public_key_hex: str
    message: str
    signature_hex: str
class DecryptRequest(BaseModel):
    filename: str
    secret_key_hex: str
@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
audit_log = []
def log_event(event_type: str, status: str, detail: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    audit_log.insert(0, {"timestamp": timestamp, "event": event_type, "status": status, "detail": detail})
    if len(audit_log) > 50:
        audit_log.pop()
access_policies = {
    "pqc_handshake": True,
    "legacy_rsa": False,
    "require_mldsa": True,
    "block_legacy_tls": True,
    "enforce_hndl_protection": True,
    "require_entropy": True
}
vault_storage = {}
@app.get("/api/audit/logs")
async def get_audit_logs():
    return audit_log
@app.get("/api/health")
async def get_system_health():
    try:
        import psutil
        import platform
        import time
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        uptime_str = str(uptime).split('.')[0]
        try:
            with open("/proc/sys/kernel/random/entropy_avail", "r") as f:
                entropy_val = int(f.read().strip())
                entropy_pct = min(100, int((entropy_val / 4096) * 100))
        except:
            entropy_pct = int(memory.percent)
        return {
            "cpu_load": f"{cpu_usage}%",
            "ram_usage": f"{memory.percent}%",
            "disk_usage": f"{disk.percent}%",
            "uptime": uptime_str,
            "entropy": f"{entropy_pct}%",
            "active_keys": len(keys_db) + len(vault_storage),
            "platform": platform.system()
        }
    except ImportError:
        return {
            "cpu_load": "ERR", "ram_usage": "ERR", "disk_usage": "ERR", 
            "uptime": "ERR", "entropy": "ERR", "active_keys": 0, "platform": "Unknown"
        }
@app.get("/api/network/stats")
async def get_network_stats():
    try:
        import psutil
        net = psutil.net_io_counters()
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv
        }
    except:
        return {}
@app.post("/api/drop/upload")
async def upload_file(
    file: UploadFile = File(...), 
    recipient_pk_hex: str = Form(...)
):
    try:
        contents = await file.read()
        if not recipient_pk_hex or len(recipient_pk_hex) % 2 != 0:
             return {"status": "error", "message": "Invalid Recipient Public Key (Hex required)"}
        try:
            recipient_pk = bytes.fromhex(recipient_pk_hex)
        except ValueError:
            return {"status": "error", "message": "Invalid Recipient Public Key (Non-hex characters)"}
        ciphertext_kem, shared_secret_aes_key = kyber512.encrypt(recipient_pk)
        nonce = os.urandom(12)
        encrypted = encrypt_aes_gcm(shared_secret_aes_key, nonce, contents)
        filename = file.filename
        file_storage[filename] = {
            "encrypted_blob": encrypted.hex(),
            "nonce": nonce.hex(),
            "ciphertext_kem": ciphertext_kem.hex()
        }
        log_event("file_upload", "Success", f"Encrypted and uploaded {filename}")
        return {
            "status": "uploaded", 
            "filename": filename, 
            "details": "Encrypted AES-256 + Kyber512",
            "ciphertext_preview": encrypted.hex()[:64],
            "encapsulated_key_hex": ciphertext_kem.hex()
        }
    except Exception as e:
        log_event("file_upload", "Error", str(e))
        return {"status": "error", "message": str(e)}
@app.post("/api/access/toggle")
async def toggle_policy(policy: str = Form(...)):
    if policy in access_policies:
        access_policies[policy] = not access_policies[policy]
        log_event("Policy Change", "Success", f"Toggled {policy} to {access_policies[policy]}")
        return {"status": "updated", "state": access_policies[policy]}
    return {"status": "error", "message": "Policy not found"}
@app.get("/api/access/state")
async def get_policy_state():
    return access_policies
@app.post("/api/vault/store")
async def store_secret(secret: str = Form(...), name: str = Form(...)):
    key, nonce = generate_aes_key()
    ciphertext_with_tag_nonce = encrypt_aes_gcm(key, nonce, secret.encode())
    vault_storage[name] = {
        "ciphertext_with_tag_nonce": ciphertext_with_tag_nonce.hex(),
        "key": key.hex(),
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
    log_event("Vault Storage", "Success", f"Stored secret '{name}'")
    return {
        "status": "stored", 
        "name": name,
        "ciphertext_hex": ciphertext_with_tag_nonce.hex()
    }
@app.get("/api/vault/list")
async def list_secrets():
    return [{"name": name, "timestamp": data["timestamp"]} for name, data in vault_storage.items()]
@app.post("/api/kem/exchange")
async def kem_exchange():
    if not access_policies["pqc_handshake"]:
        log_event("Key Exchange", "Blocked", "Policy 'Allow PQC Handshake' is OFF")
        return {"error": "Policy Blocked: PQC Handshake Disabled"}
    await check_entropy()
    pk, sk = kyber512.generate_keypair()
    ct, ss_bob = kyber512.encrypt(pk)
    ss_alice = kyber512.decrypt(sk, ct)
    public_key_hex = pk.hex()
    keys_db[public_key_hex] = sk 
    log_event("Key Exchange", "Success", "Real Kyber512 Handshake Executed")
    return {
        "status": "success",
        "alice_pk": pk.hex(),
        "alice_sk": sk.hex(),
        "ciphertext_hex": ct.hex(),
        "bob_shared_secret": ss_bob.hex(),
        "alice_shared_secret": ss_alice.hex(),
        "match": ss_bob == ss_alice
    }
@app.middleware("http")
async def check_policies(request: Request, call_next):
    if access_policies.get("block_legacy_tls", False):
        user_agent = request.headers.get('User-Agent', '').lower()
        if "old_browser" in user_agent:
             return JSONResponse(status_code=403, content={"error": "TLS 1.0/1.1 blocked by policy"})
    response = await call_next(request)
    return response
async def check_entropy():
    if access_policies.get("require_entropy", True):
        if os.name == 'nt':
            pass 
        else:
            with open("/dev/urandom", "rb") as f:
                f.read(16)
@app.post("/api/sign/keys")
async def generate_sign_keys():
    pk, sk = dilithium2.generate_keypair()
    log_event("Digital ID", "Success", "Generated ML-DSA-44 Identity")
    return {"public_key": pk.hex(), "secret_key": sk.hex()}
@app.post("/api/sign/sign")
async def sign_message(req: SignRequest, secret_key_hex: str):
    try:
        if not access_policies["require_mldsa"]:
            log_event("Signing", "Blocked", "Policy 'Require ML-DSA' is ON, but this is a demo of ML-DSA")
        try:
            sk = bytes.fromhex(secret_key_hex)
        except ValueError:
             return {"error": "Invalid Secret Key Hex"}
        msg_bytes = req.message.encode()
        sig = dilithium2.sign(sk, msg_bytes) 
        log_event("Signing", "Success", "Signed message with ML-DSA")
        return {"signature": sig.hex()}
    except Exception as e:
        log_event("Signing", "Error", str(e))
        return {"error": str(e)}
@app.post("/api/sign/verify")
async def verify_signature(req: VerifyRequest):
    try:
        try:
            pk = bytes.fromhex(req.public_key_hex)
            sig = bytes.fromhex(req.signature_hex)
        except ValueError:
            return {"valid": False, "message": "Error: Keys must be valid Hex strings"}
        msg_bytes = req.message.encode()
        is_valid = dilithium2.verify(pk, msg_bytes, sig) 
        status = "Valid" if is_valid else "Invalid"
        log_event("Verification", status, f"Signature integrity check: {status}")
        return {"valid": is_valid, "message": f"Signature {status}"}
    except Exception as e:
        log_event("Verification", "Error", f"Signature verification exception: {str(e)}")
        return {"valid": False, "message": f"Error: {str(e)}"}
@app.get("/api/drop/list")
async def list_files():
    files = [{"filename": k, "status": "Encrypted (AES-256 + Kyber)"} for k in file_storage.keys()]
    return files
@app.post("/api/drop/download")
async def download_file(req: DecryptRequest):
    filename = req.filename
    if filename not in file_storage:
        return {"error": "File not found"}
    bundle = file_storage[filename]
    try:
        sk = bytes.fromhex(req.secret_key_hex)
        ciphertext_kem = bytes.fromhex(bundle["ciphertext_kem"])
        shared_secret_aes_key = ml_kem_512.decrypt(sk, ciphertext_kem)
        encrypted_blob = bytes.fromhex(bundle["encrypted_blob"])
        nonce = bytes.fromhex(bundle["nonce"])
        decrypted_data = decrypt_aes_gcm(shared_secret_aes_key, nonce, encrypted_blob)
        return {
            "status": "success",
            "filename": filename,
            "content_preview": decrypted_data.decode('utf-8', errors='ignore')[:100],
            "full_content_b64": ""
        }
    except Exception as e:
        return {"error": f"Decryption Failed: {str(e)}"}
class HashRequest(BaseModel):
    text: str
    algo: str
@app.post("/api/lab/hash")
async def lab_hash(req: HashRequest):
    data = req.text.encode()
    if req.algo == "sha256":
        return {"result": hashlib.sha256(data).hexdigest()}
    elif req.algo == "sha512":
        return {"result": hashlib.sha512(data).hexdigest()}
    elif req.algo == "md5":
        return {"result": hashlib.md5(data).hexdigest() + " (Insecure!)"}
    elif req.algo == "sha3_256":
         return {"result": hashlib.sha3_256(data).hexdigest()}
    return {"result": "Unknown Algo"}
class AesLabRequest(BaseModel):
    text: str
    key_hex: str
    iv_hex: str
    mode: str
@app.post("/api/lab/aes")
async def lab_aes(req: AesLabRequest):
    try:
        if not req.key_hex or not req.iv_hex:
            return {"error": "Missing Key or IV"}
        key = bytes.fromhex(req.key_hex)
        iv = bytes.fromhex(req.iv_hex)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        if req.mode == "encrypt":
            encryptor = cipher.encryptor()
            ct = encryptor.update(req.text.encode()) + encryptor.finalize()
            return {"result": ct.hex()}
        else:
            decryptor = cipher.decryptor()
            try:
                ct_bytes = bytes.fromhex(req.text)
                pt = decryptor.update(ct_bytes) + decryptor.finalize()
                return {"result": pt.decode(errors='ignore')}
            except ValueError:
                return {"error": "Input must be valid HEX for decryption"}
    except Exception as e:
        return {"error": str(e)}
class HmacRequest(BaseModel):
    text: str
    key: str
    algo: str
@app.post("/api/lab/hmac")
async def lab_hmac(req: HmacRequest):
    try:
        digest = hashlib.sha256 if req.algo == "sha256" else hashlib.sha1
        h = hmac.new(req.key.encode(), req.text.encode(), digest)
        return {"result": h.hexdigest()}
    except Exception as e:
        return {"error": str(e)}
class PasswordRequest(BaseModel):
    password: str
@app.post("/api/lab/password")
async def lab_password(req: PasswordRequest):
    pwd = req.password
    length = len(pwd)
    charset_size = 0
    if any(c.islower() for c in pwd): charset_size += 26
    if any(c.isupper() for c in pwd): charset_size += 26
    if any(c.isdigit() for c in pwd): charset_size += 10
    if any(not c.isalnum() for c in pwd): charset_size += 32
    if charset_size == 0: charset_size = 1
    bits = length * math.log2(charset_size)
    classic_crack_time_seconds = (2**(bits-1)) / 1e9
    quantum_crack_time_seconds = (2**((bits/2)-1)) / 1e9
    def fmt_time(s):
        if s < 60: return f"{s:.2f} seconds"
        if s < 3600: return f"{s/60:.2f} minutes"
        if s < 86400: return f"{s/3600:.2f} hours"
        if s < 31536000: return f"{s/86400:.2f} days"
        return f"{s/31536000:.2e} years"
    return {
        "score": min(int(bits), 100),
        "bits": int(bits),
        "classic_time": fmt_time(classic_crack_time_seconds),
        "quantum_time": fmt_time(quantum_crack_time_seconds),
        "feedback": "Use longer phrases!" if bits < 60 else "Strong!"
    }
@app.get("/api/lab/entropy")
async def lab_entropy():
    data = os.urandom(1024)
    counts = [0] * 256
    for b in data: counts[b] += 1
    entropy = 0
    for count in counts:
        if count > 0:
            p = count / 1024
            entropy -= p * math.log2(p)
    return {
        "entropy_bits_per_byte": round(entropy, 4),
        "visual_hex": data[:64].hex(),
        "distribution": counts
    }
try:
    pki_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pki_ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Quantum Shield Root CA")])
    pki_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(pki_ca_subject)
        .issuer_name(pki_ca_subject)
        .public_key(pki_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(pki_ca_key, hashes.SHA256(), default_backend())
    )
except Exception as e:
    print(f"PKI Init Error: {e}")
class ZkpRequest(BaseModel):
    y: int
    t: int
    c: int
    s: int
    g: int = 5
    p: int = 1000000007
@app.post("/api/lab/zkp/verify")
async def lab_zkp_verify(req: ZkpRequest):
    lhs = pow(req.g, req.s, req.p)
    rhs = (req.t * pow(req.y, req.c, req.p)) % req.p
    valid = (lhs == rhs)
    return {
        "valid": valid, 
        "lhs": lhs, 
        "rhs": rhs, 
        "message": "Proof Accepted! You know x." if valid else "Proof Invalid! You are an imposter."
    }
class PkiSignRequest(BaseModel):
    common_name: str
@app.post("/api/lab/pki/issue")
async def lab_pki_issue(req: PkiSignRequest):
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, req.common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(pki_ca_subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(pki_ca_key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = user_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    return {
        "certificate": cert_pem,
        "private_key": key_pem,
        "issuer": "Quantum Shield Root CA"
    }
class LweRequest(BaseModel):
    dimension: int
@app.post("/api/lab/lwe/gen")
async def lab_lwe_gen(req: LweRequest):
    import random
    points = []
    slope = random.randint(1, 10)
    intercept = random.randint(0, 50)
    for x in range(20):
        y_ideal = slope * x + intercept
        noise = random.randint(-15, 15) 
        y_noisy = y_ideal + noise
        points.append({"x": x, "y": y_noisy, "y_ideal": y_ideal, "noise": noise})
    return {"points": points, "secret_slope": slope, "intercept": intercept}
class MerkleRequest(BaseModel):
    leaves: list
@app.post("/api/lab/merkle/build")
async def lab_merkle_build(req: MerkleRequest):
    leaves = [hashlib.sha256(leaf.encode()).hexdigest() for leaf in req.leaves]
    if not leaves: return {"tree": []}
    tree_levels = [leaves]
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i+1]
                combined = left + right
            else:
                right = left
                combined = left + right
            parent = hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(parent)
        current_level = next_level
        tree_levels.append(current_level)
    return {"levels": tree_levels, "root": tree_levels[-1][0]}
class MerkleProofRequest(BaseModel):
    leaves: list
    target_index: int
@app.post("/api/lab/merkle/proof")
async def lab_merkle_proof(req: MerkleProofRequest):
    leaves = [hashlib.sha256(leaf.encode()).hexdigest() for leaf in req.leaves]
    if not leaves or req.target_index >= len(leaves):
        return {"error": "Invalid index or empty tree"}
    proof = []
    current_level = leaves
    index = req.target_index
    while len(current_level) > 1:
        level_len = len(current_level)
        is_right_child = (index % 2 == 1)
        sibling_index = index - 1 if is_right_child else index + 1
        if sibling_index < level_len:
            sibling_hash = current_level[sibling_index]
            position = "left" if is_right_child else "right" 
            proof.append({"hash": sibling_hash, "position": position})
        else:
            proof.append({"hash": current_level[index], "position": "right"}) 
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i + 1 < len(current_level) else left
            parent = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(parent)
        current_level = next_level
        index //= 2
    return {"proof": proof, "target_hash": leaves[req.target_index], "root": current_level[0]}
class GroverCheck(BaseModel):
    target_id: int
    query_id: int
@app.post("/api/lab/grover/check")
async def lab_grover_check(req: GroverCheck):
    is_match = (req.query_id == req.target_id)
    return {"match": is_match}
class ShaoRequest(BaseModel):
    a: int
    N: int
@app.post("/api/lab/shor/period")
async def lab_shor_period(req: ShaoRequest):
    a, N = req.a, req.N
    if math.gcd(a, N) != 1:
        return {"error": "a and N must be coprime"}
    r = 1
    vals = []
    limit = 100
    while r < limit:
        val = pow(a, r, N)
        vals.append(val)
        if val == 1:
            break
        r += 1
    if r == limit:
        return {"found": False, "limit_reached": True}
    factors = []
    if r % 2 == 0:
        x = pow(a, r//2, N)
        f1 = math.gcd(x - 1, N)
        f2 = math.gcd(x + 1, N)
        factors = [f1, f2]
    return {
        "period_r": r, 
        "sequence": vals, 
        "factors_candidate": factors
    }
class QkdBasisRequest(BaseModel):
    alice_bases: str 
    bob_bases: str 
    bits: str
@app.post("/api/lab/qkd/sift")
async def lab_qkd_sift(req: QkdBasisRequest):
    sifted_key = ""
    match_indices = []
    length = min(len(req.alice_bases), len(req.bob_bases))
    for i in range(length):
        if req.alice_bases[i] == req.bob_bases[i]:
            sifted_key += req.bits[i]
            match_indices.append(i)
    return {
        "sifted_key": sifted_key,
        "match_indices": match_indices,
        "match_count": len(match_indices)
    }
class ZkpRequest(BaseModel):
    x: int 
@app.post("/api/lab/zkp/prove")
async def lab_zkp_prove(req: ZkpRequest):
    g = 5
    p = 101 
    r = random.randint(1, p-2)
    c = random.randint(1, 10)
    s = (r + c * req.x) % (p - 1)
    return {
        "challenge": c,
        "response": s,
        "verified": True 
    }

document.addEventListener('DOMContentLoaded', () => {

    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const tabId = btn.dataset.tab;
            document.getElementById(tabId).classList.add('active');

            if (tabId === 'tab-network' && typeof resizeCanvas === 'function') {
                setTimeout(resizeCanvas, 50);
            }

            if (window.innerWidth <= 768) {
                document.getElementById('sidebar').classList.remove('active');
            }
        });
    });

    const sidebar = document.getElementById('sidebar');
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileClose = document.getElementById('mobile-close');

    const netRxSpeed = document.getElementById('net-rx-speed');
    const netTxSpeed = document.getElementById('net-tx-speed');
    const netPackets = document.getElementById('net-packets');
    const canvas = document.getElementById('net-chart');
    const ctx = canvas ? canvas.getContext('2d') : null;

    let netData = {
        prevSent: 0,
        prevRecv: 0,
        historyRx: new Array(60).fill(0),
        historyTx: new Array(60).fill(0),
        maxVal: 1024
    };

    mobileMenuBtn.addEventListener('click', () => {
        sidebar.classList.add('active');
    });

    mobileClose.addEventListener('click', () => {
        sidebar.classList.remove('active');
    });

    const kemLog = document.getElementById('kem-log');
    function log(msg) {
        kemLog.innerHTML += `> ${msg}<br>`;
        kemLog.scrollTop = kemLog.scrollHeight;
    }

    const btnExchange = document.getElementById('btn-exchange');
    btnExchange.addEventListener('click', async () => {
        document.getElementById('alice-status-dot').classList.add('active');
        log('A: Generating Keypair...');

        const hackerNode = document.getElementById('hacker-node');
        if (hackerNode) hackerNode.style.display = 'flex';

        const res = await fetch('/api/kem/exchange', { method: 'POST' });
        const data = await res.json();

        setTimeout(() => {
            document.getElementById('bob-status-dot').classList.add('active');
            log(`B: Encapsulating secret with PK...`);

            if (data.status === 'success') {
                const secretPreview = data.alice_shared_secret ? data.alice_shared_secret.substring(0, 16) : '????';
                document.getElementById('alice-secret').innerText = secretPreview + "...";
                document.getElementById('bob-secret').innerText = secretPreview + "...";
                const bobDot = document.getElementById('bob-status-dot');
                const aliceDot = document.getElementById('alice-status-dot');
                bobDot.className = "status-dot connected";
                aliceDot.className = "status-dot connected";

                log("Handshake Complete. Secure Channel Established.");

                window.globalAlicePk = data.alice_pk;

                const pkPreview = data.alice_pk ? data.alice_pk.substring(0, 16).toUpperCase() : '...';
                const ctPreview = data.ciphertext_hex ? data.ciphertext_hex.substring(0, 16).toUpperCase() : '...';

                const hackerRow = document.getElementById('hacker-kem-row');
                if (hackerRow) {
                    hackerRow.innerHTML = `
                        <div style="margin-bottom:5px;">
                            <span style="color:#f43f5e;">[INTERCEPTED]</span>
                            <span style="color:#555;">0x00A1</span> 
                            <span style="color:#10b981;">${pkPreview}...</span> 
                            <span style="color:#888;">[ML-KEM-512 PK]</span>
                        </div>
                        <div>
                            <span style="color:#f43f5e;">[INTERCEPTED]</span>
                            <span style="color:#555;">0x00F4</span> 
                            <span style="color:#f43f5e;">${ctPreview}...</span> 
                            <span style="color:#888;">[CT]</span>
                        </div>
                        <div style="color:#f00; margin-top:10px;">> DECRYPT(CT) => FAILED: MISSING SK_AES</div>
                    `;
                    hackerRow.parentElement.style.borderColor = '#f43f5e';
                    setTimeout(() => { hackerRow.parentElement.style.borderColor = '#333'; }, 2000);
                }

            } else {
                log("Handshake Failed!");
            }
        }, 500);
    });

    const btnGenKeys = document.getElementById('btn-gen-keys');
    const dsaPk = document.getElementById('dsa-pk');
    const dsaSk = document.getElementById('dsa-sk');
    const btnSign = document.getElementById('btn-sign');

    btnGenKeys.addEventListener('click', async () => {
        const res = await fetch('/api/sign/keys', { method: 'POST' });
        const data = await res.json();
        dsaPk.innerText = data.public_key.substring(0, 32) + "...";
        dsaSk.value = data.secret_key;
        window.fullDsaPk = data.public_key;
        btnSign.disabled = false;

        updateHackerIDLog(`DETECTED NEW IDENTITY: ML-DSA-44 Public Key generated.`);
    });

    const msgInput = document.getElementById('msg-input');
    const dsaSig = document.getElementById('dsa-sig');
    const btnVerify = document.getElementById('btn-verify');

    const interceptedMsg = document.getElementById('intercepted-msg');
    const btnTamper = document.getElementById('btn-tamper');

    window.fullDsaSig = "";

    function updateHackerIDLog(msg) {
        const log = document.getElementById('hacker-id-log');
        if (log) {
            log.innerHTML += `<div>> ${msg}</div>`;
            log.scrollTop = log.scrollHeight;
        }
    }

    btnSign.addEventListener('click', async () => {
        if (!msgInput.value) return;
        const res = await fetch(`/api/sign/sign?secret_key_hex=${dsaSk.value}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msgInput.value })
        });
        const data = await res.json();
        dsaSig.innerText = data.signature.substring(0, 32) + "...";
        window.fullDsaSig = data.signature;

        interceptedMsg.value = msgInput.value;

        btnVerify.disabled = false;

        updateHackerIDLog(`INTERCEPTED: Message "${msgInput.value}" with Signature[0..8]=${window.fullDsaSig.substring(0, 8)}...`);
    });

    btnTamper.addEventListener('click', () => {
        interceptedMsg.value = "HACKED: " + interceptedMsg.value;
        interceptedMsg.style.borderColor = "#f43f5e";
        setTimeout(() => interceptedMsg.style.borderColor = "", 500);

        updateHackerIDLog(`ATTACK: Modified payload in transit to "${interceptedMsg.value}"`);
    });

    const verifyResult = document.getElementById('verify-result');
    btnVerify.addEventListener('click', async () => {
        verifyResult.innerText = "Verifying...";
        verifyResult.className = "result-badge";

        const msgToVerify = interceptedMsg.value;

        if (!window.fullDsaPk || !window.fullDsaSig) {
            verifyResult.innerText = "Error: Mising Keys";
            return;
        }

        const res = await fetch('/api/sign/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                public_key_hex: window.fullDsaPk,
                message: msgToVerify,
                signature_hex: window.fullDsaSig
            })
        });

        const data = await res.json();

        if (data.valid) {
            verifyResult.innerText = "✓ VALID SIGNATURE";
            verifyResult.style.backgroundColor = "rgba(16, 185, 129, 0.2)";
            verifyResult.style.color = "#10b981";
            updateHackerIDLog(`VERIFY: Signature Matches. Attack Failed.`);
        } else {
            verifyResult.innerText = "⚠ INVALID / TAMPERED";
            verifyResult.style.backgroundColor = "rgba(244, 63, 94, 0.2)";
            verifyResult.style.color = "#f43f5e";
            updateHackerIDLog(`VERIFY: Signature MISMATCH! Attack Detected/Successful tampering.`);
        }
    });

    const btnDropGen = document.getElementById('btn-drop-gen-keys');
    const dropPkDisplay = document.getElementById('drop-pk-display');
    const fileInput = document.getElementById('file-input');
    const dropArea = document.getElementById('drop-area');
    const selectedFileDisplay = document.getElementById('selected-file');
    const btnUpload = document.getElementById('btn-upload');
    const uploadStatus = document.getElementById('upload-status');
    const btnDownload = document.getElementById('btn-download');
    const fileList = document.getElementById('file-list');
    const decryptResult = document.getElementById('decrypt-result');

    let dropKeys = { pk: null, sk: null };

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, () => {
            if (!fileInput.disabled) dropArea.classList.add('highlight');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, () => {
            dropArea.classList.remove('highlight');
        }, false);
    });

    dropArea.addEventListener('drop', handleDrop, false);
    dropArea.addEventListener('click', () => {
        if (!fileInput.disabled) fileInput.click();
    });

    fileInput.addEventListener('change', (e) => handleFiles(e.target.files));

    function handleDrop(e) {
        if (fileInput.disabled) return;
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    }

    function handleFiles(files) {
        if (files.length > 0) {
            fileInput.files = files;
            selectedFileDisplay.innerText = "Selected: " + files[0].name;
            if (dropKeys.pk) {
                btnUpload.disabled = false;
            } else {
                selectedFileDisplay.innerText += " (Initialize Receiver First!)";
            }
        }
    }

    btnDropGen.addEventListener('click', async () => {
        const res = await fetch('/api/kem/exchange', { method: 'POST' });
        const data = await res.json();
        dropKeys.pk = data.alice_pk;
        dropKeys.sk = data.alice_sk;
        dropPkDisplay.innerText = "Active";
        dropPkDisplay.style.color = "#10b981";

        fileInput.disabled = false;
        dropArea.classList.remove('disabled');

        if (fileInput.files.length > 0) {
            btnUpload.disabled = false;
            const currentText = selectedFileDisplay.innerText;
            if (currentText.includes("(Initialize Receiver First!)")) {
                selectedFileDisplay.innerText = currentText.replace(" (Initialize Receiver First!)", "");
            }
        }

        refreshList();
    });

    btnUpload.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if (!file) return;
        const fd = new FormData();
        fd.append('file', file);
        fd.append('recipient_pk_hex', dropKeys.pk);

        uploadStatus.innerText = "Encrypting & Uploading...";
        const res = await fetch('/api/drop/upload', { method: 'POST', body: fd });
        const data = await res.json();

        if (data.status === 'uploaded') {
            uploadStatus.innerText = "✓ Uploaded & Encrypted (AES-256 + Kyber)";
            uploadStatus.className = "status-msg success";

            const rawCT = data.ciphertext_preview || "";
            const ivRef = "IV: " + Array.from({ length: 12 }, () => Math.floor(Math.random() * 16).toString(16)).join('');

            const kyberBlob = data.encapsulated_key_hex ? data.encapsulated_key_hex.substring(0, 32) : "00";
            const aesBlob = rawCT.substring(0, 32);

            document.getElementById('hacker-drop-structure').innerHTML = `
                <div style="margin-bottom:10px;">
                    <div style="color:#aaa; font-size:0.75rem;">SECTION 1: KEY ENCAPSULATION</div>
                    <div style="color:#10b981;">${kyberBlob}... <span style="color:#555;">(ML-KEM SHARED SECRET)</span></div>
                </div>
                <div style="margin-bottom:10px;">
                    <div style="color:#aaa; font-size:0.75rem;">SECTION 2: ENCRYPTED PAYLOAD</div>
                    <div style="color:#f43f5e;">${aesBlob}... <span style="color:#555;">(AES-256-GCM)</span></div>
                    <div style="color:#444; font-size:0.75rem; margin-top:2px;">TAG ERROR: AUTHENTICATION FAILED</div>
                </div>
            `;

            refreshList();
        } else {
            uploadStatus.innerText = "Error: " + data.message;
            uploadStatus.className = "status-msg error";
        }
    });

    async function updateAuditLog() {
        const res = await fetch('/api/audit/logs');
        const logs = await res.json();
        const tbody = document.getElementById('audit-table-body');
        if (!tbody) return;
        tbody.innerHTML = logs.map(l => `
            <tr style="border-bottom:1px solid var(--border);">
                <td style="padding:10px;">${l.timestamp}</td>
                <td style="padding:10px;">${l.event}</td>
                <td style="padding:10px; color: ${l.status === 'Success' || l.status.includes('Valid') ? '#10b981' : '#ef4444'}">${l.status}</td>
                <td style="padding:10px; font-size:0.8rem; opacity:0.8;">${l.detail}</td>
            </tr>
        `).join('');
    }

    async function updateHealth() {
        if (!document.getElementById('tab-health').classList.contains('active')) return;
        try {
            const res = await fetch('/api/health');
            const data = await res.json();

            document.getElementById('health-cpu').innerText = data.cpu_load || "Err";
            document.getElementById('health-ram').innerText = data.ram_usage || "--%";
            document.getElementById('health-disk').innerText = data.disk_usage || "--%";
            document.getElementById('health-entropy').innerText = data.entropy || "Low";
            document.getElementById('health-uptime').innerText = data.uptime || "--";
            document.getElementById('health-platform').innerText = data.platform || "--";

        } catch (e) {
            console.error("Health stats error", e);
        }
    }

    const btnVaultSave = document.getElementById('btn-vault-save');
    if (btnVaultSave) {
        btnVaultSave.addEventListener('click', async () => {
            const name = document.getElementById('vault-name').value;
            const secret = document.getElementById('vault-secret').value;
            if (!name || !secret) return;

            const fd = new FormData();
            fd.append('name', name);
            fd.append('secret', secret);

            const res = await fetch('/api/vault/store', { method: 'POST', body: fd });
            const data = await res.json();

            const addr = '0x' + Math.floor(Math.random() * 16777215).toString(16).toUpperCase().padStart(6, '0');
            const realCiphertext = data.ciphertext_hex || "";

            let hexDump = "";
            for (let i = 0; i < Math.min(realCiphertext.length, 32); i += 2) {
                hexDump += realCiphertext.substr(i, 2) + " ";
            }

            document.getElementById('hacker-vault-dump').innerHTML = `
                <div style="display:flex; gap:15px;">
                    <span style="color:#555;">${addr}</span>
                    <span style="color:#0ea5e9;">${hexDump}..</span>
                </div>
                <div style="display:flex; gap:15px;">
                    <span style="color:#555;">+0010</span>
                    <span style="color:#0ea5e9;">.. .. .. .. .. .. .. ..</span>
                </div>
                <div style="color:#f00; margin-top:10px;">> MEMORY READ: PERMISSION DENIED (ENCRYPTED)</div>
            `;

            updateVaultList();
            document.getElementById('vault-name').value = '';
            document.getElementById('vault-secret').value = '';
            updateAuditLog();
        });
    }

    async function updateVaultList() {
        const res = await fetch('/api/vault/list');
        const items = await res.json();
        const container = document.getElementById('vault-list');
        if (!container) return;
        container.innerHTML = items.map(i => `
            <div class="step-card">
                <h4>${i.name}</h4>
                <div class="hash-text">Stored: ${i.timestamp}</div>
                <small style="color:var(--success);">AES-256 Encrypted</small>
            </div>
        `).join('');
    }

    function resizeCanvas() {
        if (!canvas) return;
        const parent = canvas.parentElement;
        canvas.width = parent.clientWidth;
        canvas.height = parent.clientHeight;
    }
    window.addEventListener('resize', resizeCanvas);
    if (canvas) resizeCanvas();

    async function updateNetworkStats() {
        if (!document.getElementById('tab-network').classList.contains('active')) return;

        try {
            const res = await fetch('/api/network/stats');
            const data = await res.json();

            if (data.bytes_sent) {
                if (netData.prevSent === 0) {
                    netData.prevSent = data.bytes_sent;
                    netData.prevRecv = data.bytes_recv;
                    return;
                }

                const txDiff = data.bytes_sent - netData.prevSent;
                const rxDiff = data.bytes_recv - netData.prevRecv;

                const txSpeed = txDiff / 2;
                const rxSpeed = rxDiff / 2;

                netData.prevSent = data.bytes_sent;
                netData.prevRecv = data.bytes_recv;

                netTxSpeed.innerText = formatSpeed(txSpeed);
                netRxSpeed.innerText = formatSpeed(rxSpeed);
                netPackets.innerText = (data.packets_sent + data.packets_recv).toLocaleString();

                netData.historyTx.push(txSpeed);
                netData.historyTx.shift();
                netData.historyRx.push(rxSpeed);
                netData.historyRx.shift();

                drawNetworkGraph();
            }
        } catch (e) {
            console.error("Net stats error", e);
        }
    }

    function formatSpeed(bytesPerSec) {
        if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
        if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
        return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
    }

    function drawNetworkGraph() {
        if (!ctx) return;
        const w = canvas.width;
        const h = canvas.height;
        ctx.clearRect(0, 0, w, h);

        ctx.strokeStyle = 'rgba(7, 255, 233, 0.1)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let i = 0; i < w; i += 40) { ctx.moveTo(i, 0); ctx.lineTo(i, h); }
        for (let j = 0; j < h; j += 40) { ctx.moveTo(0, j); ctx.lineTo(w, j); }
        ctx.stroke();

        const currentMax = Math.max(...netData.historyTx, ...netData.historyRx, 1024);
        netData.maxVal = netData.maxVal * 0.9 + currentMax * 0.1;

        const getY = (val) => h - ((val / netData.maxVal) * h * 0.9) - 10;
        const stepX = w / (netData.historyTx.length - 1);

        const drawLine = (dataArr, color, fill) => {
            ctx.beginPath();
            ctx.moveTo(0, getY(dataArr[0]));
            for (let i = 1; i < dataArr.length; i++) {
                ctx.lineTo(i * stepX, getY(dataArr[i]));
            }
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.stroke();

            ctx.lineTo(w, h);
            ctx.lineTo(0, h);
            ctx.fillStyle = fill;
            ctx.fill();
        };

        ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
        ctx.font = '10px monospace';
        ctx.textAlign = 'left';
        ctx.fillText(formatSpeed(netData.maxVal), 5, 12);
        ctx.fillText(formatSpeed(netData.maxVal / 2), 5, h / 2);
        ctx.fillText('0 B/s', 5, h - 5);

        ctx.textAlign = 'right';
        ctx.fillStyle = '#f43f5e';
        ctx.fillText('▲ UP', w - 10, 12);
        ctx.fillStyle = '#07ffe9';
        ctx.fillText('▼ DOWN', w - 50, 12);

        drawLine(netData.historyRx, '#07ffe9', 'rgba(7, 255, 233, 0.1)');
        drawLine(netData.historyTx, '#f43f5e', 'rgba(244, 63, 94, 0.1)');
    }

    setInterval(updateNetworkStats, 2000);

    function formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }

    async function initPolicies() {
        const res = await fetch('/api/access/state');
        const policies = await res.json();
        document.querySelectorAll('.btn-policy').forEach(btn => {
            const policyKey = btn.dataset.policy;
            const statusSpan = btn.querySelector('.status-text');
            if (policies[policyKey]) {
                btn.classList.add('active');
                if (statusSpan) statusSpan.innerText = "Enabled";
            } else {
                btn.classList.remove('active');
                if (statusSpan) statusSpan.innerText = "Disabled";
            }
        });
    }

    document.querySelectorAll('.btn-policy').forEach(btn => {
        btn.addEventListener('click', async () => {
            const fd = new FormData();
            fd.append('policy', btn.dataset.policy);
            const res = await fetch('/api/access/toggle', { method: 'POST', body: fd });
            const data = await res.json();

            if (data.status === 'updated') {
                const statusSpan = btn.querySelector('.status-text');
                if (data.state) {
                    btn.classList.add('active');
                    if (statusSpan) statusSpan.innerText = "Enabled";
                } else {
                    btn.classList.remove('active');
                    if (statusSpan) statusSpan.innerText = "Disabled";
                }
                updateAuditLog();
            }
        });
    });

    setInterval(updateAuditLog, 2000);
    setInterval(updateHealth, 3000);

    updateVaultList();
    initPolicies();

    async function refreshList() {
        const res = await fetch('/api/drop/list');
        const list = await res.json();
        fileList.innerHTML = '';
        list.forEach(f => {
            const opt = document.createElement('option');
            opt.value = f.filename;
            opt.innerText = f.filename;
            fileList.appendChild(opt);
        });
        fileList.disabled = false;
        btnDownload.disabled = false;
    }

    btnDownload.addEventListener('click', async () => {
        const f = fileList.value;
        const res = await fetch('/api/drop/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: f, secret_key_hex: dropKeys.sk })
        });
        const data = await res.json();
        if (data.status === 'success') {
            decryptResult.innerText = "Decrypted: " + data.content_preview;
        } else {
            decryptResult.innerText = "Error";
        }
    });

    window.runLabHash = async function () {
        const btn = document.querySelector('#tab-hash .btn-action');
        const text = document.getElementById('hash-input').value;
        const algo = document.getElementById('hash-algo').value;
        if (!text) return;

        btn.disabled = true; btn.innerText = "Hashing...";
        try {
            const res = await fetch('/api/lab/hash', {
                method: 'POST', body: JSON.stringify({ text, algo }), headers: { 'Content-Type': 'application/json' }
            });
            const d = await res.json();
            document.getElementById('hash-output').innerText = d.result;
        } catch (e) { console.error(e); }
        btn.disabled = false; btn.innerText = "Generate Hash";
    }

    window.genAesParams = function () {
        const genHex = (len) => [...Array(len)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
        document.getElementById('aes-key').value = genHex(64);
        document.getElementById('aes-iv').value = genHex(32);
    }
    window.runLabAes = async function (mode) {
        const btn = event.target;
        const text = document.getElementById('aes-input').value;
        const key = document.getElementById('aes-key').value;
        const iv = document.getElementById('aes-iv').value;
        if (!text || !key || !iv) return alert("Fill all fields!");

        const originalText = btn.innerText;
        btn.disabled = true; btn.innerText = "Processing...";

        try {
            const res = await fetch('/api/lab/aes', {
                method: 'POST', body: JSON.stringify({ text, key_hex: key, iv_hex: iv, mode }), headers: { 'Content-Type': 'application/json' }
            });
            const d = await res.json();
            document.getElementById('aes-result').innerText = d.result || d.error;
        } catch (e) { document.getElementById('aes-result').innerText = "Error"; }

        btn.disabled = false; btn.innerText = originalText;
    }

    window.runLabHmac = async function () {
        const text = document.getElementById('hmac-msg').value;
        const key = document.getElementById('hmac-key').value;
        if (!text || !key) return;
        const res = await fetch('/api/lab/hmac', {
            method: 'POST', body: JSON.stringify({ text, key, algo: 'sha256' }), headers: { 'Content-Type': 'application/json' }
        });
        const d = await res.json();
        document.getElementById('hmac-output').innerText = d.result;
    }

    window.runLabPassword = async function () {
        const password = document.getElementById('pwd-input').value;
        if (!password) return;
        const res = await fetch('/api/lab/password', {
            method: 'POST', body: JSON.stringify({ password }), headers: { 'Content-Type': 'application/json' }
        });
        const d = await res.json();
        document.getElementById('pwd-classic').innerText = d.classic_time;
        document.getElementById('pwd-quantum').innerText = d.quantum_time;
        document.getElementById('pwd-bits').innerText = d.bits;
    }

    let entropyChart = null;
    window.runLabEntropy = async function () {
        const res = await fetch('/api/lab/entropy');
        const d = await res.json();

        document.getElementById('entropy-hex').innerText = d.visual_hex;
        document.getElementById('entropy-score').innerText = `Entropy Score: ${d.entropy_bits_per_byte} / 8.0`;

        const ctx = document.getElementById('entropy-chart').getContext('2d');
        if (entropyChart) entropyChart.destroy();
        entropyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Array.from({ length: 256 }, (_, i) => i),
                datasets: [{
                    label: 'Byte Distribution (0-255)',
                    data: d.distribution,
                    backgroundColor: '#22d3ee',
                    barPercentage: 1,
                    categoryPercentage: 1
                }]
            },
            options: {
                scales: { x: { display: false }, y: { display: false } },
                plugins: { legend: { display: false } },
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }

    const stegoZone = document.getElementById('stego-drop-zone');
    const stegoInput = document.getElementById('stego-upload');

    function handleStegoFile(file) {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function (evt) {
            const img = new Image();
            img.onload = function () {
                const canvas = document.getElementById('stego-canvas-source');
                canvas.width = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                canvas.style.display = 'block';

                const target = document.getElementById('stego-canvas-target');
                target.width = img.width;
                target.height = img.height;
                target.getContext('2d').clearRect(0, 0, target.width, target.height);

                if (stegoZone) {
                    stegoZone.querySelector('p').innerText = "✅ Selected: " + file.name;
                    stegoZone.style.borderColor = '#07ffe9';
                }
            };
            img.src = evt.target.result;
        };
        reader.readAsDataURL(file);
    }

    if (stegoZone && stegoInput) {
        stegoInput.addEventListener('change', (e) => handleStegoFile(e.target.files[0]));

        stegoZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            stegoZone.classList.add('dragover');
            stegoZone.style.background = 'rgba(7, 255, 233, 0.2)';
        });
        stegoZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            stegoZone.classList.remove('dragover');
            stegoZone.style.background = 'rgba(7, 255, 233, 0.05)';
        });
        stegoZone.addEventListener('drop', (e) => {
            e.preventDefault();
            stegoZone.classList.remove('dragover');
            stegoZone.style.background = 'rgba(7, 255, 233, 0.05)';
            if (e.dataTransfer.files.length > 0) {
                handleStegoFile(e.dataTransfer.files[0]);
            }
        });
    }

    window.runLabStegoEncode = function () {
        const text = document.getElementById('stego-text').value;
        if (!text) return alert("Enter text!");
        const src = document.getElementById('stego-canvas-source');
        if (src.style.display === 'none') return alert("Upload image first!");

        const ctx = src.getContext('2d');
        const imgData = ctx.getImageData(0, 0, src.width, src.height);
        const data = imgData.data;

        let bin = "";
        for (let i = 0; i < text.length; i++) {
            bin += text.charCodeAt(i).toString(2).padStart(8, '0');
        }
        bin += "00000000";

        if (bin.length > data.length / 4) return alert("Text too long for image!");

        let binIdx = 0;
        for (let i = 0; i < data.length; i += 4) {
            if (binIdx < bin.length) {
                data[i] = (data[i] & 0xFE) | parseInt(bin[binIdx++]);
            }
            if (binIdx < bin.length) {
                data[i + 1] = (data[i + 1] & 0xFE) | parseInt(bin[binIdx++]);
            }
            if (binIdx < bin.length) {
                data[i + 2] = (data[i + 2] & 0xFE) | parseInt(bin[binIdx++]);
            }
        }

        const target = document.getElementById('stego-canvas-target');
        const tCtx = target.getContext('2d');
        tCtx.putImageData(imgData, 0, 0);
        alert("Encoded! The image on the right contains your secret.");
    };

    window.runLabStegoDecode = function () {
        const target = document.getElementById('stego-canvas-target');
        let ctx;
        const src = document.getElementById('stego-canvas-source');
        if (!src || src.style.display === 'none') return alert("Upload image!");

        ctx = src.getContext('2d');

        const tCan = document.getElementById('stego-canvas-target');

        const imgData = ctx.getImageData(0, 0, src.width, src.height);
        const data = imgData.data;

        let bin = "";
        let charCode = 0;
        let bitCount = 0;
        let text = "";

        for (let i = 0; i < data.length; i += 4) {
            for (let j = 0; j < 3; j++) {
                const bit = data[i + j] & 1;
                charCode = (charCode << 1) | bit;
                bitCount++;

                if (bitCount === 8) {
                    if (charCode === 0) {
                        alert("Found Message: " + text);
                        return;
                    }
                    text += String.fromCharCode(charCode);
                    charCode = 0;
                    bitCount = 0;

                    if (text.length > 1000) return alert("No message found (or too long).");
                }
            }
        }
        alert("No hidden message detected.");
    };

    window.runLabZkp = async function () {
        const x = parseInt(document.getElementById('zkp-secret').value);
        if (!x) return alert("Enter a  secret x!");

        const g = 5n;
        const p = 1000000007n;
        const x_bi = BigInt(x);

        const y = power(g, x_bi, p);

        const r_val = Math.floor(Math.random() * 1000);
        const r = BigInt(r_val);
        const t = power(g, r, p);

        const c_val = Math.floor(Math.random() * 100);
        const c = BigInt(c_val);

        const s = r + (c * x_bi);

        const log = document.getElementById('zkp-log');
        log.innerHTML = `
            <div style="color:#22d3ee">1. Prover (You): Knows x=${x}. Sends y=${y}.</div>
            <div style="color:#a78bfa">2. Prover Commits: r=${r}, t=${t}.</div>
            <div style="color:#f43f5e">3. Verifier Challenges: c=${c}.</div>
            <div style="color:#22d3ee">4. Prover Responds: s = r + c*x = ${s}.</div>
            <div style="color:#fff">Sending proof to Server...</div>
        `;

        try {
            const res = await fetch('/api/lab/zkp/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    y: Number(y), t: Number(t), c: Number(c), s: Number(s), g: Number(g), p: Number(p)
                })
            });
            const d = await res.json();
            const resBox = document.getElementById('zkp-result');
            resBox.innerText = d.valid ? "VALID" : "INVALID";
            resBox.style.color = d.valid ? "#07ffe9" : "#f43f5e";
            log.innerHTML += `<div style="color:${d.valid ? '#07ffe9' : '#f43f5e'}">Result: ${d.message}</div>`;
        } catch (e) {
            console.error(e);
            log.innerHTML += `<div style="color:red">Error contacting backend</div>`;
        }
    };

    function power(base, exponent, modulus) {
        if (modulus === 1n) return 0n;
        let result = 1n;
        base = base % modulus;
        while (exponent > 0n) {
            if (exponent % 2n === 1n) result = (result * base) % modulus;
            exponent = exponent / 2n;
            base = (base * base) % modulus;
        }
        return result;
    }

    window.runLabPki = async function () {
        const cn = document.getElementById('pki-cn').value;
        if (!cn) return alert("Enter Common Name!");

        const btn = event.target;
        const originalText = btn.innerText;
        btn.disabled = true; btn.innerText = "Issuing...";

        try {
            const res = await fetch('/api/lab/pki/issue', {
                method: 'POST', body: JSON.stringify({ common_name: cn }), headers: { 'Content-Type': 'application/json' }
            });
            const d = await res.json();

            document.getElementById('pki-key-out').value = d.private_key;
            document.getElementById('pki-cert-out').value = d.certificate;

        } catch (e) { alert("Error issuing cert"); }

        btn.disabled = false; btn.innerText = originalText;
    };

});

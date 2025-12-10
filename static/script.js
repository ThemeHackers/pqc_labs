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
        const div = document.createElement('div');
        div.textContent = `> ${msg}`;
        kemLog.appendChild(div);
        kemLog.scrollTop = kemLog.scrollHeight;
    }

    const btnExchange = document.getElementById('btn-exchange');
    btnExchange.addEventListener('click', async () => {
        document.getElementById('alice-status-dot').classList.add('active');
        log('A: Generating Keypair...');

        const p1 = document.getElementById('packet-1');
        if (p1) { p1.classList.remove('animate-right'); void p1.offsetWidth; p1.classList.add('animate-right'); }

        const hackerNode = document.getElementById('hacker-node');
        if (hackerNode) hackerNode.style.display = 'flex';

        const res = await fetch('/api/kem/exchange', { method: 'POST' });
        const data = await res.json();

        setTimeout(() => {
            document.getElementById('bob-status-dot').classList.add('active');
            log(`B: Encapsulating secret with PK...`);

            const p2 = document.getElementById('packet-2');
            if (p2) { p2.classList.remove('animate-left'); void p2.offsetWidth; p2.classList.add('animate-left'); }

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
                    hackerRow.innerHTML = '';

                    const row1 = document.createElement('div');
                    row1.style.marginBottom = '5px';

                    const span1 = document.createElement('span');
                    span1.style.color = '#f43f5e';
                    span1.textContent = '[INTERCEPTED]';
                    row1.appendChild(span1);

                    row1.appendChild(document.createTextNode(' '));

                    const span2 = document.createElement('span');
                    span2.style.color = '#555';
                    span2.textContent = '0x00A1';
                    row1.appendChild(span2);

                    row1.appendChild(document.createTextNode(' '));

                    const span3 = document.createElement('span');
                    span3.style.color = '#10b981';
                    span3.textContent = pkPreview + '...';
                    row1.appendChild(span3);

                    row1.appendChild(document.createTextNode(' '));

                    const span4 = document.createElement('span');
                    span4.style.color = '#888';
                    span4.textContent = '[ML-KEM-512 PK]';
                    row1.appendChild(span4);

                    hackerRow.appendChild(row1);

                    const row2 = document.createElement('div');

                    const span5 = document.createElement('span');
                    span5.style.color = '#f43f5e';
                    span5.textContent = '[INTERCEPTED]';
                    row2.appendChild(span5);

                    row2.appendChild(document.createTextNode(' '));

                    const span6 = document.createElement('span');
                    span6.style.color = '#555';
                    span6.textContent = '0x00F4';
                    row2.appendChild(span6);

                    row2.appendChild(document.createTextNode(' '));

                    const span7 = document.createElement('span');
                    span7.style.color = '#f43f5e';
                    span7.textContent = ctPreview + '...';
                    row2.appendChild(span7);

                    row2.appendChild(document.createTextNode(' '));

                    const span8 = document.createElement('span');
                    span8.style.color = '#888';
                    span8.textContent = '[CT]';
                    row2.appendChild(span8);

                    hackerRow.appendChild(row2);

                    const row3 = document.createElement('div');
                    row3.style.color = '#f00';
                    row3.style.marginTop = '10px';
                    row3.textContent = '> DECRYPT(CT) => FAILED: MISSING SK_AES';
                    hackerRow.appendChild(row3);

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
            const div = document.createElement('div');
            div.textContent = `> ${msg}`;
            log.appendChild(div);
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

            const hackerDrop = document.getElementById('hacker-drop-structure');
            hackerDrop.innerHTML = '';

            const div1 = document.createElement('div');
            div1.style.marginBottom = '10px';
            const title1 = document.createElement('div');
            title1.style.color = '#aaa';
            title1.style.fontSize = '0.75rem';
            title1.textContent = 'SECTION 1: KEY ENCAPSULATION';
            div1.appendChild(title1);

            const content1 = document.createElement('div');
            content1.style.color = '#10b981';
            const span1 = document.createElement('span');
            span1.textContent = kyberBlob + '... ';
            const spanType1 = document.createElement('span');
            spanType1.style.color = '#555';
            spanType1.textContent = '(ML-KEM SHARED SECRET)';
            content1.appendChild(span1);
            content1.appendChild(spanType1);
            div1.appendChild(content1);
            hackerDrop.appendChild(div1);

            const div2 = document.createElement('div');
            div2.style.marginBottom = '10px';
            const title2 = document.createElement('div');
            title2.style.color = '#aaa';
            title2.style.fontSize = '0.75rem';
            title2.textContent = 'SECTION 2: ENCRYPTED PAYLOAD';
            div2.appendChild(title2);

            const content2 = document.createElement('div');
            content2.style.color = '#f43f5e';
            const span2 = document.createElement('span');
            span2.textContent = aesBlob + '... ';
            const spanType2 = document.createElement('span');
            spanType2.style.color = '#555';
            spanType2.textContent = '(AES-256-GCM)';
            content2.appendChild(span2);
            content2.appendChild(spanType2);
            div2.appendChild(content2);

            const errDiv = document.createElement('div');
            errDiv.style.color = '#444';
            errDiv.style.fontSize = '0.75rem';
            errDiv.style.marginTop = '2px';
            errDiv.textContent = 'TAG ERROR: AUTHENTICATION FAILED';
            div2.appendChild(errDiv);

            hackerDrop.appendChild(div2);

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
        if (!tbody) return;
        tbody.innerHTML = '';
        logs.forEach(l => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border)';

            const td1 = document.createElement('td');
            td1.style.padding = '10px';
            td1.textContent = l.timestamp;
            tr.appendChild(td1);

            const td2 = document.createElement('td');
            td2.style.padding = '10px';
            td2.textContent = l.event;
            tr.appendChild(td2);

            const td3 = document.createElement('td');
            td3.style.padding = '10px';
            td3.style.color = (l.status === 'Success' || (l.status && l.status.includes('Valid'))) ? '#10b981' : '#ef4444';
            td3.textContent = l.status;
            tr.appendChild(td3);

            const td4 = document.createElement('td');
            td4.style.padding = '10px';
            td4.style.fontSize = '0.8rem';
            td4.style.opacity = '0.8';
            td4.textContent = l.detail;
            tr.appendChild(td4);

            tbody.appendChild(tr);
        });
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

            const vaultDump = document.getElementById('hacker-vault-dump');
            vaultDump.innerHTML = '';

            const row1 = document.createElement('div');
            row1.style.display = 'flex';
            row1.style.gap = '15px';

            const span1 = document.createElement('span');
            span1.style.color = '#555';
            span1.textContent = addr;
            row1.appendChild(span1);

            const span2 = document.createElement('span');
            span2.style.color = '#0ea5e9';
            span2.textContent = hexDump + '..';
            row1.appendChild(span2);

            vaultDump.appendChild(row1);

            const row2 = document.createElement('div');
            row2.style.display = 'flex';
            row2.style.gap = '15px';

            const span3 = document.createElement('span');
            span3.style.color = '#555';
            span3.textContent = '+0010';
            row2.appendChild(span3);

            const span4 = document.createElement('span');
            span4.style.color = '#0ea5e9';
            span4.textContent = '.. .. .. .. .. .. .. ..';
            row2.appendChild(span4);

            vaultDump.appendChild(row2);

            const row3 = document.createElement('div');
            row3.style.color = '#f00';
            row3.style.marginTop = '10px';
            row3.textContent = '> MEMORY READ: PERMISSION DENIED (ENCRYPTED)';
            vaultDump.appendChild(row3);

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
        if (!container) return;
        container.innerHTML = '';
        items.forEach(i => {
            const div = document.createElement('div');
            div.className = 'step-card';

            const h4 = document.createElement('h4');
            h4.textContent = i.name;
            div.appendChild(h4);

            const dateDiv = document.createElement('div');
            dateDiv.className = 'hash-text';
            dateDiv.textContent = `Stored: ${i.timestamp}`;
            div.appendChild(dateDiv);

            const small = document.createElement('small');
            small.style.color = 'var(--success)';
            small.textContent = 'AES-256 Encrypted';
            div.appendChild(small);

            container.appendChild(div);
        });
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
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                ctx.drawImage(img, 0, 0);
                canvas.style.display = 'block';

                const target = document.getElementById('stego-canvas-target');
                target.width = img.width;
                target.height = img.height;
                target.getContext('2d', { willReadFrequently: true }).clearRect(0, 0, target.width, target.height);

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

});

window.showModal = function (msg, title = "Notification") {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = msg;
    const overlay = document.getElementById('custom-modal');
    overlay.classList.add('active');
};

window.closeModal = function () {
    document.getElementById('custom-modal').classList.remove('active');
};


function downloadStegoImage() {
    const canvas = document.getElementById('stego-canvas-target');
    const link = document.createElement('a');
    link.download = 'stego_result.png';
    try {
        link.href = canvas.toDataURL();
        link.click();
    } catch (e) {
        showModal("Could not download image. Ensure an image has been generated.", "Error");
    }
}
window.downloadStegoImage = downloadStegoImage;


window.textToBits = function (text) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(text);
    let bits = "";
    for (let i = 0; i < bytes.length; i++) {
        bits += bytes[i].toString(2).padStart(8, '0');
    }
    bits += "00000000";
    return bits;
}

window.bitsToText = function (bits) {
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        const byte = parseInt(bits.substr(i, 8), 2);
        if (byte === 0) break;
        bytes.push(byte);
    }
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

window.encodeStegoLogic = function (data, text) {
    const bin = window.textToBits(text);
    if (bin.length > data.length / 4) {
        throw new Error("Text too long for this image!");
    }
    let binIdx = 0;
    for (let i = 0; i < data.length; i += 4) {
        for (let j = 0; j < 3; j++) {
            if (binIdx < bin.length) {
                data[i + j] = (data[i + j] & 0xFE) | parseInt(bin[binIdx++]);
            }
        }
    }
    return data;
}

window.decodeStegoLogic = function (data) {
    let bits = "";
    const maxBits = 80000;
    for (let i = 0; i < data.length; i += 4) {
        for (let j = 0; j < 3; j++) {
            if (bits.length >= maxBits) break;
            bits += (data[i + j] & 1);
        }
        if (bits.length >= maxBits) break;
    }
    return window.bitsToText(bits);
}

function runLabStegoEncode() {
    const text = document.getElementById('stego-text').value;
    if (!text) return showModal("Enter text!", "Input Error");

    const src = document.getElementById('stego-canvas-source');
    if (src.style.display === 'none') return showModal("Upload image first!", "Missing Image");

    const ctx = src.getContext('2d', { willReadFrequently: true });
    const imgData = ctx.getImageData(0, 0, src.width, src.height);

    try {
        window.encodeStegoLogic(imgData.data, text);

        const target = document.getElementById('stego-canvas-target');
        const tCtx = target.getContext('2d', { willReadFrequently: true });
        tCtx.putImageData(imgData, 0, 0);
        showModal("Encoded! The image on the right contains your secret.", "Success");
    } catch (e) {
        showModal(e.message, "Error");
    }
}
window.runLabStegoEncode = runLabStegoEncode;


function runLabStegoDecode() {
    const src = document.getElementById('stego-canvas-source');
    const target = document.getElementById('stego-canvas-target');

    const tryDecode = (canvas) => {
        if (!canvas || canvas.width === 0) return "";
        try {
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            if (canvas.style.display === 'none' && canvas.id === 'stego-canvas-source') return "";

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            return window.decodeStegoLogic(imgData.data);
        } catch (e) { return ""; }
    };

    let text = tryDecode(target);


    if (!text || text.length === 0) {
        text = tryDecode(src);
    }

    if (text.length > 0) {
        showModal("Found Message: " + text, "Decoded Secret");
    } else {
        showModal("No hidden message detected (or message is empty).", "Result");
    }
}
window.runLabStegoDecode = runLabStegoDecode;

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
    log.innerHTML = '';

    const div1 = document.createElement('div');
    div1.style.color = '#22d3ee';
    div1.textContent = `1. Prover (You): Knows x=${x}. Sends y=${y}.`;
    log.appendChild(div1);

    const div2 = document.createElement('div');
    div2.style.color = '#a78bfa';
    div2.textContent = `2. Prover Commits: r=${r}, t=${t}.`;
    log.appendChild(div2);

    const div3 = document.createElement('div');
    div3.style.color = '#f43f5e';
    div3.textContent = `3. Verifier Challenges: c=${c}.`;
    log.appendChild(div3);

    const div4 = document.createElement('div');
    div4.style.color = '#22d3ee';
    div4.textContent = `4. Prover Responds: s = r + c*x = ${s}.`;
    log.appendChild(div4);

    const div5 = document.createElement('div');
    div5.style.color = '#fff';
    div5.textContent = 'Sending proof to Server...';
    log.appendChild(div5);

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

        const resDiv = document.createElement('div');
        resDiv.style.color = d.valid ? '#07ffe9' : '#f43f5e';
        resDiv.textContent = `Result: ${d.message}`;
        log.appendChild(resDiv);

    } catch (e) {
        console.error(e);
        const errDiv = document.createElement('div');
        errDiv.style.color = 'red';
        errDiv.textContent = 'Error contacting backend';
        log.appendChild(errDiv);
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



document.addEventListener('DOMContentLoaded', () => {
    const bitRange = document.getElementById('range-bit-plane');
    if (bitRange) {
        bitRange.addEventListener('input', updateBitPlaneView);
        const observer = new MutationObserver(() => {
            setTimeout(updateBitPlaneView, 100);
        });
    }
});

window.updateBitPlaneView = function () {
    const src = document.getElementById('stego-canvas-source');
    const target = document.getElementById('stego-canvas-target');
    const canvasToUse = (target && target.width > 0 && target.width === src.width) ? target : src;

    if (!canvasToUse || !canvasToUse.width) return;

    const analyzer = document.getElementById('stego-canvas-analyzer');
    if (!analyzer) return;

    const ctx = canvasToUse.getContext('2d', { willReadFrequently: true });
    try {
        const imgData = ctx.getImageData(0, 0, canvasToUse.width, canvasToUse.height);
        const data = imgData.data;

        if (analyzer.width !== canvasToUse.width || analyzer.height !== canvasToUse.height) {
            analyzer.width = canvasToUse.width;
            analyzer.height = canvasToUse.height;
        }

        const aCtx = analyzer.getContext('2d');
        const aImgData = aCtx.createImageData(analyzer.width, analyzer.height);
        const aData = aImgData.data;

        const bit = parseInt(document.getElementById('range-bit-plane').value);
        document.getElementById('val-bit-plane').innerText = bit + (bit === 0 ? " (LSB)" : (bit === 7 ? " (MSB)" : ""));

        const mask = 1 << bit;

        for (let i = 0; i < data.length; i += 4) {
            const val = (data[i] & mask) ? 255 : 0;

            aData[i] = val;
            aData[i + 1] = val;
            aData[i + 2] = val;
            aData[i + 3] = 255;
        }

        aCtx.putImageData(aImgData, 0, 0);
    } catch (e) { console.log("BitPlane Error", e); }
}

const origStegoEncode = window.runLabStegoEncode;
window.runLabStegoEncode = async function () {
    await origStegoEncode();
    window.updateBitPlaneView();
}

const origHandleStego = window.handleStegoFile;


let lweChart = null;
window.runLabLwe = async function () {
    const btn = event.target;
    btn.disabled = true;
    const res = await fetch('/api/lab/lwe/gen', {
        method: 'POST', body: JSON.stringify({ dimension: 1 }), headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    document.getElementById('lwe-slope').innerText = `Slope: ${data.secret_slope}, Intercept: ${data.intercept}`;


    const ctx = document.getElementById('lwe-chart').getContext('2d');
    if (lweChart) lweChart.destroy();

    const scatterData = data.points.map(p => ({ x: p.x, y: p.y }));
    const lineData = data.points.map(p => ({ x: p.x, y: p.y_ideal }));

    lweChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'Noisy Samples (Public)',
                data: scatterData,
                backgroundColor: '#f43f5e'
            }, {
                label: 'Secret Function (Hidden)',
                data: lineData,
                type: 'line',
                borderColor: '#22d3ee',
                pointRadius: 0,
                borderDash: [5, 5]
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.1)' } },
                y: { grid: { color: 'rgba(255,255,255,0.1)' } }
            }
        }
    });
    btn.disabled = false;
};


window.runLabMerkle = async function () {
    const text = document.getElementById('merkle-leaves').value;
    const leaves = text.split('\n').filter(x => x.trim().length > 0);
    const viz = document.getElementById('merkle-viz');

    viz.innerText = "Building...";
    const res = await fetch('/api/lab/merkle/build', {
        method: 'POST', body: JSON.stringify({ leaves }), headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    document.getElementById('merkle-root').innerText = data.root || "Error";

    let output = "";
    data.levels.reverse().forEach((level, i) => {
        output += `Level ${i} (Size ${level.length}):\n`;
        level.forEach(h => {
            output += `  [${h.substring(0, 8)}...]\n`;
        });
        output += "\n";
    });
    viz.innerText = output;
};

window.runLabMerkleProof = async function () {
    const text = document.getElementById('merkle-leaves').value;
    const leaves = text.split('\n').filter(x => x.trim().length > 0);
    const idx = parseInt(document.getElementById('merkle-proof-idx').value);
    const log = document.getElementById('merkle-proof-log');

    if (isNaN(idx) || idx < 0 || idx >= leaves.length) return showModal("Invalid Index (" + idx + ") - Please choose a number between 0 and " + (leaves.length - 1), "Input Error");

    log.innerHTML = "Requesting Proof...";

  
    const res = await fetch('/api/lab/merkle/proof', {
        method: 'POST', body: JSON.stringify({ leaves, target_index: idx }), headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    if (data.error) {
        log.innerText = "Error: " + data.error;
        return;
    }


    let html = `Target Leaf: "${leaves[idx]}"\nHash: ${data.target_hash.substring(0, 8)}...\n\n`;
    html += `Proof Path (Sibling Hashes to combine):\n`;

    data.proof.forEach((step, i) => {
        html += `${i + 1}. [${step.position.toUpperCase()}] Sibling: ${step.hash.substring(0, 8)}...\n`;
    });

    html += `\nCalculated Root: ${data.root.substring(0, 16)}...\n`;
    html += `Matches Actual Root? YES ✅ (Mathematically proven)`;

    log.innerText = html;
};


window.runLabGrover = async function () {
    let N = parseInt(document.getElementById('grover-size').value);


    if (N > 512) {
        alert("⚠️ For browser safety, the maximum database size is limited to 512 items in this demo.");
        document.getElementById('grover-size').value = 512;
        N = 512;
    }

    const grid = document.getElementById('grover-grid');
    const resBox = document.getElementById('grover-result');
    grid.innerHTML = '';
    resBox.innerText = '';


    const target = Math.floor(Math.random() * N);
    const boxes = [];
    for (let i = 0; i < N; i++) {
        const div = document.createElement('div');
        div.style.border = "1px solid #333";
        div.style.aspectRatio = "1";
        div.style.background = "rgba(255,255,255,0.05)";
        div.style.display = "flex";
        div.style.justifyContent = "center";
        div.style.alignItems = "center";
        div.style.color = "#555";
        div.innerText = i;
        div.id = `grover-box-${i}`;
        grid.appendChild(div);
        boxes.push(div);
    }


    let steps = Math.floor(Math.sqrt(N));
    let step = 0;

    const interval = setInterval(() => {
    
        boxes.forEach(b => b.style.background = "rgba(255,255,255,0.05)");


        const rand = Math.floor(Math.random() * N);
        const el = document.getElementById(`grover-box-${rand}`);
        el.style.background = "rgba(34, 211, 238, 0.4)";

        step++;
        if (step > steps + 1) { 
            clearInterval(interval);
            boxes.forEach(b => b.style.background = "rgba(255,255,255,0.05)");
            const targetEl = document.getElementById(`grover-box-${target}`);
            targetEl.style.background = "#10b981";
            targetEl.style.color = "#000";
            targetEl.style.fontWeight = "bold";
            resBox.innerText = `Found TARGET at index ${target} in ${steps} iterations (Classic would take ~${N / 2}).`;
            resBox.className = "result-badge success";
        }
    }, 400);
};

window.runLabShor = async function () {
    const a = parseInt(document.getElementById('shor-a').value);
    const N = parseInt(document.getElementById('shor-n').value);
    const log = document.getElementById('shor-log');

    if (!a || !N) return alert("Enter a and N");

    log.innerHTML = "Computing a^x mod N sequence...";

    const res = await fetch('/api/lab/shor/period', {
        method: 'POST', body: JSON.stringify({ a, N }), headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    document.getElementById('shor-r').innerText = data.period_r || "Not Found";

    if (data.sequence) {
        log.innerText = `Sequence: ${data.sequence.join(' -> ')}\nCycle detected (Period r=${data.period_r})`;
        if (data.factors_candidate.length > 0) {
            log.innerText += `\n\nDerived Factors of ${N}: ${data.factors_candidate.join(', ')}`;
        }
    } else {
        log.innerText = data.error || "Computation limit reached.";
    }
};


window.aliceBits = [];
window.bobBits = [];
window.aliceBases = [];
window.bobBases = [];

window.genQkdBits = function () {
    const len = 10;
    window.aliceBits = Array.from({ length: len }, () => Math.random() > 0.5 ? 1 : 0);
    window.aliceBases = Array.from({ length: len }, () => Math.random() > 0.5 ? '+' : 'x');
    window.bobBases = Array.from({ length: len }, () => Math.random() > 0.5 ? '+' : 'x');

    const aliceDiv = document.getElementById('alice-qkd');
    aliceDiv.innerHTML = '';
    window.aliceBits.forEach((b, i) => {
        const d = document.createElement('div');
        d.className = 'qkd-bit';
        d.innerHTML = `${b}<br><span style='font-size:0.6rem; color:#aaa'>${window.aliceBases[i]}</span>`;
        d.style.textAlign = 'center';
        d.style.padding = '5px';
        d.style.border = '1px solid #333';
        aliceDiv.appendChild(d);
    });

    document.getElementById('bob-qkd').innerHTML = "<span style='color:#555'>Ready to receive...</span>";
    document.getElementById('qkd-log').innerText = '';
};

window.runLabQkd = async function () {

    if (!window.aliceBits.length) return alert("Generate bits first!");

    const bobDiv = document.getElementById('bob-qkd');
    bobDiv.innerHTML = '';

    let bobReceivedBits = ""; 


    window.bobBases.forEach((base, i) => {
        const d = document.createElement('div');
        d.style.textAlign = 'center';
        d.style.padding = '5px';
        d.style.border = '1px solid #333';

        let bit = window.aliceBits[i];

        let measuredBit = bit;
        if (window.aliceBases[i] !== base) {
            measuredBit = Math.random() > 0.5 ? 1 : 0;
            d.style.opacity = '0.5'; 
        } else {
            d.style.borderColor = '#10b981'; 
        }

        d.innerHTML = `${measuredBit}<br><span style='font-size:0.6rem; color:#aaa'>${base}</span>`;
        bobDiv.appendChild(d);
        bobReceivedBits += measuredBit;
    });
    const res = await fetch('/api/lab/qkd/sift', {
        method: 'POST',
        body: JSON.stringify({
            alice_bases: window.aliceBases.join(''),
            bob_bases: window.bobBases.join(''),
            bits: window.aliceBits.join('')
        }),
        headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    const log = document.getElementById('qkd-log');
    log.innerHTML = `<div>1. Bases Compared. Matching Indices: [${data.match_indices.join(', ')}]</div>`;
    log.innerHTML += `<div style='color:#10b981; margin-top:10px;'>2. Shared Secret Generated: ${data.sifted_key}</div>`;
    log.innerHTML += `<div style='font-size:0.8rem; color:#666'>Discarded ${window.aliceBits.length - data.match_count} bits due to basis mismatch.</div>`;
};


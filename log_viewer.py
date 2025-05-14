import os
import time
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading

app = Flask(__name__)
socketio = SocketIO(app)

# Log dosya yolları
ACCESS_LOG = "access.log"
SECURITY_LOG = "security_monitor.log"

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

def read_last_n_lines(file_path, n=100):
    """Bir dosyanın son n satırını okur"""
    try:
        if not os.path.exists(file_path):
            return []
            
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            return lines[-n:] if lines else []
    except Exception as e:
        print(f"Dosya okuma hatası: {e}")
        return []

@app.route('/logs/access')
def get_access_logs():
    """Access log verilerini döndürür"""
    logs = read_last_n_lines(ACCESS_LOG)
    return jsonify(logs=logs)

@app.route('/logs/security')
def get_security_logs():
    """Security log verilerini döndürür"""
    logs = read_last_n_lines(SECURITY_LOG)
    return jsonify(logs=logs)

def monitor_logs():
    """Log dosyalarını izler ve değişiklik olduğunda Socket.IO ile bildirir"""
    access_position = 0
    security_position = 0
    
    try:
        while True:
            # Access log kontrolü
            if os.path.exists(ACCESS_LOG):
                current_size = os.path.getsize(ACCESS_LOG)
                if current_size > access_position:
                    with open(ACCESS_LOG, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(access_position)
                        new_lines = f.readlines()
                        if new_lines:
                            socketio.emit('new_access_logs', {'logs': new_lines})
                    access_position = current_size
            
            # Security log kontrolü
            if os.path.exists(SECURITY_LOG):
                current_size = os.path.getsize(SECURITY_LOG)
                if current_size > security_position:
                    with open(SECURITY_LOG, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(security_position)
                        new_lines = f.readlines()
                        if new_lines:
                            socketio.emit('new_security_logs', {'logs': new_lines})
                    security_position = current_size
            
            time.sleep(1)  # Her saniye kontrol et
    except Exception as e:
        print(f"Log izleme hatası: {e}")

@socketio.on('connect')
def handle_connect():
    """Client bağlantısı kurulduğunda çalışır"""
    # Bağlantı kurulduğunda mevcut logları gönder
    access_logs = read_last_n_lines(ACCESS_LOG)
    security_logs = read_last_n_lines(SECURITY_LOG)
    
    socketio.emit('initial_access_logs', {'logs': access_logs})
    socketio.emit('initial_security_logs', {'logs': security_logs})

if __name__ == '__main__':
    # Log izleme thread'ini başlat
    log_thread = threading.Thread(target=monitor_logs)
    log_thread.daemon = True
    log_thread.start()
    
    # Web sunucusunu başlat
    socketio.run(app, debug=True, host='0.0.0.0', port=5001) 
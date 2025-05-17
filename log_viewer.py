import os
import time
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
from dotenv import load_dotenv
import pandas as pd
from collections import defaultdict
import json
from datetime import datetime, timedelta
import re

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app)

# Log dosya yolları
ACCESS_LOG = "access.log"
SECURITY_LOG = "security_monitor.log"

# Port numarasını .env'den al (yoksa 5001 kullan)
PORT = int(os.getenv("PORT", 5001))

# Analiz verilerini saklamak için global değişkenler
traffic_stats = {
    'total_requests': 0,
    'requests_by_ip': defaultdict(int),
    'requests_by_endpoint': defaultdict(int),
    'requests_by_method': defaultdict(int),
    'requests_by_status': defaultdict(int),
    'requests_by_hour': defaultdict(int),
    'attack_types': defaultdict(int),
    'geo_locations': defaultdict(int)
}

def parse_log_line(line):
    """Log satırını parse eder ve analiz için veri çıkarır"""
    try:
        # IP adresi
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        ip = ip_match.group(1) if ip_match else 'unknown'
        
        # HTTP metodu
        method_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)', line)
        method = method_match.group(1) if method_match else 'unknown'
        
        # Endpoint
        endpoint_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^"]+)"', line)
        endpoint = endpoint_match.group(2) if endpoint_match else 'unknown'
        
        # Status code
        status_match = re.search(r'" (\d{3}) ', line)
        status = status_match.group(1) if status_match else 'unknown'
        
        # Timestamp
        timestamp_match = re.search(r'\[([^\]]+)\]', line)
        timestamp = timestamp_match.group(1) if timestamp_match else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Saldırı türü tespiti
        attack_type = 'normal'
        
        # SQL Injection tespiti
        sql_patterns = [
            r'union\s+select', r'select\s+from', r'drop\s+table',
            r'--', r';--', r'/\*', r'\*/', r'exec\s+xp_',
            r'exec\s+sp_', r'waitfor\s+delay', r'benchmark\s*\(',
            r'sleep\s*\('
        ]
        if any(re.search(pattern, line.lower()) for pattern in sql_patterns):
            attack_type = 'SQL Injection'
            print(f"SQL Injection tespit edildi: {line}")
        
        # XSS tespiti
        xss_patterns = [
            r'<script>', r'javascript:', r'onerror=', r'onload=',
            r'eval\(', r'document\.cookie', r'alert\(',
            r'confirm\(', r'prompt\(', r'innerHTML',
            r'outerHTML', r'appendChild'
        ]
        if attack_type == 'normal' and any(re.search(pattern, line.lower()) for pattern in xss_patterns):
            attack_type = 'XSS'
            print(f"XSS tespit edildi: {line}")
        
        # Brute Force tespiti
        if attack_type == 'normal' and re.search(r'failed.*login|invalid.*password|wrong.*password|too\s+many\s+failed\s+attempts', line.lower()):
            attack_type = 'Brute Force'
            print(f"Brute Force tespit edildi: {line}")
        
        # DDoS tespiti
        if attack_type == 'normal' and re.search(r'too\s+many\s+requests|rate\s+limit\s+exceeded|connection\s+limit|connection\s+reset', line.lower()):
            attack_type = 'DDoS'
            print(f"DDoS tespit edildi: {line}")
        
        # Path Traversal tespiti
        if attack_type == 'normal' and any(pattern in line.lower() for pattern in ['../', '..\\', '/etc/passwd', 'c:\\windows', 'etc/shadow']):
            attack_type = 'Path Traversal'
            print(f"Path Traversal tespit edildi: {line}")
        
        # Command Injection tespiti
        if attack_type == 'normal' and any(pattern in line.lower() for pattern in [';ls', ';cat', ';rm', ';wget', ';curl', ';bash', ';sh', ';python']):
            attack_type = 'Command Injection'
            print(f"Command Injection tespit edildi: {line}")
        
        return {
            'ip': ip,
            'method': method,
            'endpoint': endpoint,
            'status': status,
            'timestamp': timestamp,
            'attack_type': attack_type
        }
    except Exception as e:
        print(f"Log parse hatası: {e}")
        return None

def update_traffic_stats(log_data):
    """Trafik istatistiklerini günceller"""
    if not log_data:
        return
        
    traffic_stats['total_requests'] += 1
    traffic_stats['requests_by_ip'][log_data['ip']] += 1
    traffic_stats['requests_by_endpoint'][log_data['endpoint']] += 1
    traffic_stats['requests_by_method'][log_data['method']] += 1
    traffic_stats['requests_by_status'][log_data['status']] += 1
    
    # Saat bazlı analiz
    try:
        # Timestamp'i parse et
        timestamp = datetime.strptime(log_data['timestamp'], '%Y-%m-%d %H:%M:%S')
        hour = timestamp.hour
        
        # Saat bazlı istek sayısını güncelle
        hour_key = str(hour)
        traffic_stats['requests_by_hour'][hour_key] = traffic_stats['requests_by_hour'].get(hour_key, 0) + 1
        
        print(f"Trafik istatistiği güncellendi - Saat: {hour}, İstek Sayısı: {traffic_stats['requests_by_hour'][hour_key]}")
    except Exception as e:
        print(f"Saat bazlı analiz hatası: {e}")
    
    # Saldırı türü analizi
    if log_data['attack_type'] != 'normal':
        traffic_stats['attack_types'][log_data['attack_type']] += 1
        print(f"Saldırı tespit edildi: {log_data['attack_type']} - IP: {log_data['ip']}")

def get_analytics_data():
    """Analitik verileri hazırlar ve döndürür"""
    # Saat bazlı verileri hazırla
    hourly_data = {}
    for hour in range(24):
        hourly_data[str(hour)] = traffic_stats['requests_by_hour'].get(str(hour), 0)
    
    # Saldırı dağılımını hazırla
    attack_distribution = dict(traffic_stats['attack_types'])
    
    # En aktif saldırganları hazırla
    top_ips = dict(sorted(traffic_stats['requests_by_ip'].items(), key=lambda x: x[1], reverse=True)[:10])
    
    analytics_data = {
        'traffic_stats': traffic_stats,
        'hourly_trend': hourly_data,
        'attack_distribution': attack_distribution,
        'top_ips': top_ips
    }
    
    print(f"Analitik veriler hazırlandı:")
    print(f"- Toplam İstek: {traffic_stats['total_requests']}")
    print(f"- Toplam Saldırı: {sum(traffic_stats['attack_types'].values())}")
    print(f"- Saatlik Dağılım: {hourly_data}")
    print(f"- Saldırı Dağılımı: {attack_distribution}")
    print(f"- En Aktif IP'ler: {top_ips}")
    
    return analytics_data

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/api/analytics')
def get_analytics():
    """Analiz verilerini döndürür"""
    return jsonify({
        'traffic_stats': traffic_stats,
        'hourly_trend': dict(traffic_stats['requests_by_hour']),
        'attack_distribution': dict(traffic_stats['attack_types']),
        'top_ips': dict(sorted(traffic_stats['requests_by_ip'].items(), key=lambda x: x[1], reverse=True)[:10]),
        'top_endpoints': dict(sorted(traffic_stats['requests_by_endpoint'].items(), key=lambda x: x[1], reverse=True)[:10])
    })

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
                            # Yeni logları analiz et
                            for line in new_lines:
                                log_data = parse_log_line(line)
                                if log_data:
                                    update_traffic_stats(log_data)
                            
                            # Socket.IO ile verileri gönder
                            socketio.emit('new_access_logs', {'logs': new_lines})
                            socketio.emit('analytics_update', get_analytics_data())
                            print(f"Yeni access logları gönderildi: {len(new_lines)} satır")
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
                            print(f"Yeni security logları gönderildi: {len(new_lines)} satır")
                    security_position = current_size
            
            time.sleep(1)  # Her saniye kontrol et
    except Exception as e:
        print(f"Log izleme hatası: {e}")

@socketio.on('connect')
def handle_connect():
    """Client bağlantısı kurulduğunda çalışır"""
    print("Yeni client bağlandı")
    # Bağlantı kurulduğunda mevcut logları gönder
    access_logs = read_last_n_lines(ACCESS_LOG)
    security_logs = read_last_n_lines(SECURITY_LOG)
    
    socketio.emit('initial_access_logs', {'logs': access_logs})
    socketio.emit('initial_security_logs', {'logs': security_logs})
    socketio.emit('analytics_update', get_analytics_data())
    print(f"İlk loglar gönderildi - Access: {len(access_logs)} satır, Security: {len(security_logs)} satır")

if __name__ == '__main__':
    # Log izleme thread'ini başlat
    log_thread = threading.Thread(target=monitor_logs)
    log_thread.daemon = True
    log_thread.start()
    
    # Web sunucusunu başlat
    print(f"Log görüntüleyici başlatılıyor... PORT: {PORT}")
    socketio.run(app, debug=True, host='0.0.0.0', port=PORT, allow_unsafe_werkzeug=True) 
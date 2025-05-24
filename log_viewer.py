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
import geoip2.database
import ipaddress

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
socketio = SocketIO(app)

# Log dosya yolları
ACCESS_LOG = "access.log"
SECURITY_LOG = "security_monitor.log"

# Port numarasını .env'den al (yoksa 5001 kullan)
PORT = int(os.getenv("PORT", 5001))

# GeoIP veritabanı yolu
GEOIP_DB = "data/GeoLite2-City.mmdb"

# GeoIP Reader
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB)
    print(f"GeoIP veritabanı başarıyla yüklendi: {GEOIP_DB}")
except Exception as e:
    print(f"GeoIP veritabanı yüklenirken hata oluştu: {e}")

# Analiz verilerini saklamak için global değişkenler
traffic_stats = {
    'total_requests': 0,
    'requests_by_ip': defaultdict(int),
    'requests_by_endpoint': defaultdict(int),
    'requests_by_method': defaultdict(int),
    'requests_by_status': defaultdict(int),
    'requests_by_hour': defaultdict(int),
    'normal_requests_by_hour': defaultdict(int),  # Normal trafik için saatlik istatistik
    'attack_requests_by_hour': defaultdict(int),  # Saldırı trafiği için saatlik istatistik
    'attack_types': defaultdict(int),
    'geo_locations': {},  # IP bazlı konum bilgileri
    'attack_locations': {}  # Saldırı yapılan konumlar
}

def get_ip_location(ip):
    """IP adresinden coğrafi konum bilgisi alır"""
    if not geoip_reader:
        return None
    
    try:
        # Private IP adreslerini atla
        if ipaddress.ip_address(ip).is_private:
            return None
        
        # GeoIP veritabanından konum bilgisi al
        response = geoip_reader.city(ip)
        return {
            'ip': ip,
            'country': response.country.name,
            'country_code': response.country.iso_code,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except Exception as e:
        print(f"IP konum bilgisi alınırken hata: {e} - IP: {ip}")
        return None

def calculate_attack_confidence(line, pattern_matches, total_patterns):
    """Saldırı tespiti doğruluk oranını hesaplar"""
    if pattern_matches == 0:
        return 0.0
    
    # Temel doğruluk oranı: eşleşen desen sayısı / toplam desen sayısı
    base_confidence = (pattern_matches / total_patterns) * 100
    
    # Ek faktörlere göre doğruluk oranını ayarla
    # Örneğin: Birden fazla saldırı deseni, HTTP metodu, URL kompleksliği, vb.
    
    # Belirli kritik desenlerin varlığı doğruluk oranını artırır
    critical_patterns = ['SELECT * FROM', 'DROP TABLE', '<script>alert', 'rm -rf', '/etc/passwd', '/bin/bash', 
                        'union select', 'information_schema', 'alert(', 'javascript:', 'onload=']
    for critical_pattern in critical_patterns:
        if critical_pattern.lower() in line.lower():
            base_confidence += 25  # Artırıldı
    
    # URL'de kritik parametreler varsa doğruluk oranını artır
    if any(param in line.lower() for param in ['id=', 'password=', 'user=', 'username=', 'pass=']):
        base_confidence += 15  # Artırıldı
    
    # 4xx veya 5xx HTTP durum kodları doğruluk oranını artırır
    status_match = re.search(r'" ([45]\d{2}) ', line)
    if status_match:
        base_confidence += 20  # Artırıldı
    
    # Doğruluk oranını 0-100 aralığında sınırla
    confidence = min(max(base_confidence, 0), 100)
    
    return confidence

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
        
        # Timestamp - Apache log formatını destekle
        timestamp_match = re.search(r'\[([^\]]+)\]', line)
        if timestamp_match:
            timestamp_str = timestamp_match.group(1)
            # Apache format: [24/May/2025:19:05:03 +0300]
            if '/' in timestamp_str and ':' in timestamp_str:
                try:
                    # Apache formatını parse et
                    dt_part = timestamp_str.split(' ')[0]  # "24/May/2025:19:05:03"
                    timestamp = datetime.strptime(dt_part, '%d/%b/%Y:%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                except:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp = timestamp_str
        else:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Saldırı türü tespiti
        attack_type = 'normal'
        confidence = 0.0  # Doğruluk oranı
        
        # SQL Injection tespiti
        sql_patterns = [
            r'union\s+select', r'select\s+from', r'drop\s+table',
            r'--', r';--', r'/\*', r'\*/', r'exec\s+xp_',
            r'exec\s+sp_', r'waitfor\s+delay', r'benchmark\s*\(',
            r'sleep\s*\(', r'1=1', r'or\s+1=1', r"'\s+or\s+'1'='1",
            r'delete\s+from', r'insert\s+into', r'update\s+.*\s+set',
            r'information_schema', r'sysobjects', r'substring\(',
            r'convert\(', r'cast\(', r';\s*--'
        ]
        sql_matches = sum(1 for pattern in sql_patterns if re.search(pattern, line.lower()))
        if sql_matches > 0:
            confidence = calculate_attack_confidence(line, sql_matches, len(sql_patterns))
            if confidence >= 15:
                attack_type = 'SQL Injection'
                print(f"SQL Injection tespit edildi: {line} (Doğruluk: {confidence:.1f}%)")
        
        # XSS tespiti
        if attack_type == 'normal':
            xss_patterns = [
                r'<script>', r'</script>', r'javascript:', r'onerror=', r'onload=',
                r'eval\(', r'document\.cookie', r'alert\(',
                r'confirm\(', r'prompt\(', r'innerHTML',
                r'outerHTML', r'appendChild', r'onmouseover',
                r'onmouseout', r'onkeypress', r'onfocus',
                r'onblur', r'style=', r'<img[^>]+src=[^>]+>', 
                r'<iframe', r'<object', r'data:text/html',
                r'base64', r'fromCharCode', r'&#x'
            ]
            xss_matches = sum(1 for pattern in xss_patterns if re.search(pattern, line.lower()))
            if xss_matches > 0:
                confidence = calculate_attack_confidence(line, xss_matches, len(xss_patterns))
                if confidence >= 15:
                    attack_type = 'XSS'
                    print(f"XSS tespit edildi: {line} (Doğruluk: {confidence:.1f}%)")
        
        # Brute Force tespiti
        if attack_type == 'normal':
            brute_patterns = [
                r'failed.*login', r'invalid.*password', r'wrong.*password', 
                r'too\s+many\s+failed\s+attempts', r'incorrect.*password',
                r'authentication\s+failed', r'login\s+failed', r'access\s+denied',
                r'invalid\s+credentials', r'multiple\s+login\s+attempts',
                r'account\s+locked', r'multiple\s+authentication\s+failures'
            ]
            brute_matches = sum(1 for pattern in brute_patterns if re.search(pattern, line.lower()))
            if brute_matches > 0:
                confidence = calculate_attack_confidence(line, brute_matches, len(brute_patterns))
                if confidence >= 15:
                    attack_type = 'Brute Force'
                    print(f"Brute Force tespit edildi: {line} (Doğruluk: {confidence:.1f}%)")
        
        # DDoS tespiti
        if attack_type == 'normal':
            ddos_patterns = [
                r'too\s+many\s+requests', r'rate\s+limit\s+exceeded', 
                r'connection\s+limit', r'connection\s+reset',
                r'request\s+flood', r'service\s+unavailable', r'server\s+overload',
                r'bandwidth\s+exceeded', r'resource\s+exhaustion',
                r'concurrent\s+connection\s+limit'
            ]
            ddos_matches = sum(1 for pattern in ddos_patterns if re.search(pattern, line.lower()))
            if ddos_matches > 0:
                confidence = calculate_attack_confidence(line, ddos_matches, len(ddos_patterns))
                if confidence >= 15:
                    attack_type = 'DDoS'
                    print(f"DDoS tespit edildi: {line} (Doğruluk: {confidence:.1f}%)")
        
        # Path Traversal tespiti
        if attack_type == 'normal':
            path_patterns = [
                r'\.\./', r'\.\.\\', r'/etc/passwd', r'c:\\windows', 
                r'etc/shadow', r'\.\.%2f', r'\.\.%5c', r'%2e%2e%2f',
                r'%252e%252e%252f', r'/proc/self', r'/var/log', 
                r'boot.ini', r'/system32/', r'/windows/system', r'etc/hosts'
            ]
            path_matches = sum(1 for pattern in path_patterns if pattern in line.lower())
            if path_matches > 0:
                confidence = calculate_attack_confidence(line, path_matches, len(path_patterns))
                if confidence >= 15:
                    attack_type = 'Path Traversal'
                    print(f"Path Traversal tespit edildi: {line} (Doğruluk: {confidence:.1f}%)")
        
        # Command Injection tespiti
        if attack_type == 'normal':
            cmd_patterns = [
                r';ls', r';cat', r';rm', r';wget', r';curl', r';bash', 
                r';sh', r';python', r'&& ls', r'& dir', r'| cat', 
                r'`cat', r'$(cat', r'| id', r'; id', r'&& id', 
                r'`id`', r'system\(', r'exec\(', r'shell_exec', 
                r'passthru\(', r'popen\('
            ]
            cmd_matches = sum(1 for pattern in cmd_patterns if pattern in line.lower())
            if cmd_matches > 0:
                confidence = calculate_attack_confidence(line, cmd_matches, len(cmd_patterns))
                if confidence >= 15:
                    attack_type = 'Command Injection'
                    print(f"Command Injection tespit edildi: {line} (Doğruluk: {confidence:.1f}%)")
        
        # Coğrafi konum bilgisini al
        location = None
        if ip != 'unknown':
            location = get_ip_location(ip)
        
        return {
            'ip': ip,
            'method': method,
            'endpoint': endpoint,
            'status': status,
            'timestamp': timestamp,
            'attack_type': attack_type,
            'confidence': confidence,
            'location': location
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
        
        # Normal trafik için saatlik istatistik
        if log_data['attack_type'] == 'normal':
            traffic_stats['normal_requests_by_hour'][hour_key] = traffic_stats['normal_requests_by_hour'].get(hour_key, 0) + 1
        
        # Saldırı trafiği için saatlik istatistik
        if log_data['attack_type'] != 'normal':
            traffic_stats['attack_requests_by_hour'][hour_key] = traffic_stats['attack_requests_by_hour'].get(hour_key, 0) + 1
        
        print(f"Trafik istatistiği güncellendi - Saat: {hour}, İstek Sayısı: {traffic_stats['requests_by_hour'][hour_key]}")
    except Exception as e:
        print(f"Saat bazlı analiz hatası: {e}")
    
    # Saldırı türü analizi
    if log_data['attack_type'] != 'normal':
        traffic_stats['attack_types'][log_data['attack_type']] += 1
        print(f"Saldırı tespit edildi: {log_data['attack_type']} - IP: {log_data['ip']} - Doğruluk: {log_data['confidence']:.1f}%")
    
    # Coğrafi konum bilgisi
    if log_data['location']:
        ip = log_data['ip']
        location = log_data['location']
        
        # IP bazlı konum bilgilerini kaydet
        traffic_stats['geo_locations'][ip] = location
        
        # Saldırı yapılan konumları kaydet
        if log_data['attack_type'] != 'normal':
            if ip not in traffic_stats['attack_locations']:
                traffic_stats['attack_locations'][ip] = {
                    'location': location,
                    'attack_type': log_data['attack_type'],
                    'confidence': log_data['confidence'],
                    'count': 1
                }
            else:
                traffic_stats['attack_locations'][ip]['count'] += 1
                # Saldırı tipini güncelleme
                traffic_stats['attack_locations'][ip]['attack_type'] = log_data['attack_type']
                traffic_stats['attack_locations'][ip]['confidence'] = log_data['confidence']

def get_analytics_data():
    """Analitik verileri hazırlar ve döndürür"""
    # Saat bazlı verileri hazırla
    hourly_data = {}
    normal_hourly_data = {}
    attack_hourly_data = {}
    
    for hour in range(24):
        hour_key = str(hour)
        hourly_data[hour_key] = traffic_stats['requests_by_hour'].get(hour_key, 0)
        normal_hourly_data[hour_key] = traffic_stats['normal_requests_by_hour'].get(hour_key, 0)
        attack_hourly_data[hour_key] = traffic_stats['attack_requests_by_hour'].get(hour_key, 0)
    
    # Saldırı dağılımını hazırla
    attack_distribution = dict(traffic_stats['attack_types'])
    
    # En aktif saldırganları hazırla - istek sayısına göre sıralayıp ilk 10 tanesini al
    top_ips_raw = sorted(traffic_stats['requests_by_ip'].items(), key=lambda x: x[1], reverse=True)[:10]
    
    # IP'lerin sadece saldırı yapanları değil, en çok istek atanları göster
    top_ips = {}
    for ip, count in top_ips_raw:
        # Saldırı yapan IP'leri belirleme
        is_attacker = False
        for attack_ip in traffic_stats['attack_locations'].keys():
            if ip == attack_ip:
                is_attacker = True
                break
        
        # Top listesine ekle (saldırı yapanlar + normal trafikte aktif olanlar)
        top_ips[ip] = count
    
    # Tüm konum verilerini hazırla
    locations = [loc for loc in traffic_stats['geo_locations'].values() if loc]
    
    # Saldırı konumlarını hazırla
    attack_locations = list(traffic_stats['attack_locations'].values())
    
    analytics_data = {
        'traffic_stats': traffic_stats,
        'hourly_trend': hourly_data,
        'normal_hourly_trend': normal_hourly_data,
        'attack_hourly_trend': attack_hourly_data,
        'attack_distribution': attack_distribution,
        'top_ips': top_ips,
        'locations': locations,
        'attack_locations': attack_locations
    }
    
    print(f"Analitik veriler hazırlandı:")
    print(f"- Toplam İstek: {traffic_stats['total_requests']}")
    print(f"- Toplam Saldırı: {sum(traffic_stats['attack_types'].values())}")
    print(f"- En Aktif IP'ler: {len(top_ips)}")
    print(f"- Saatlik Dağılım: {hourly_data}")
    print(f"- Saldırı Dağılımı: {attack_distribution}")
    print(f"- Toplam Konum Sayısı: {len(locations)}")
    print(f"- Saldırı Konum Sayısı: {len(attack_locations)}")
    
    return analytics_data

def monitor_logs():
    """Log dosyalarını izler ve değişiklik olduğunda Socket.IO ile bildirir"""
    access_position = 0
    security_position = 0
    
    # İlk başlangıçta mevcut tüm logları parse et
    if os.path.exists(ACCESS_LOG):
        print("Mevcut access.log dosyası parse ediliyor...")
        with open(ACCESS_LOG, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            for line in lines:
                log_data = parse_log_line(line)
                if log_data:
                    update_traffic_stats(log_data)
        access_position = os.path.getsize(ACCESS_LOG)
        print(f"Access.log parse tamamlandı: {len(lines)} satır işlendi")

    if os.path.exists(SECURITY_LOG):
        print("Mevcut security.log dosyası parse ediliyor...")
        with open(SECURITY_LOG, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            for line in lines:
                # Security loglarını da analiz et
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    
                    # Saldırı tipini belirle - app.py'deki tehdit tiplerini doğrudan kullan
                    attack_type = "Security Issue"  # Varsayılan tip
                    confidence = 50.0  # Varsayılan doğruluk oranı
                    
                    # app.py'deki tüm tehdit tiplerini kontrol et
                    # WARNING - {threat_type} tespiti: formatını yakala
                    threat_type_match = re.search(r'WARNING - (.*?) tespiti:', line)
                    if threat_type_match:
                        attack_type = threat_type_match.group(1)
                        confidence = 85.0
                    
                    # Log verisini oluştur
                    location = get_ip_location(ip)
                    log_data = {
                        'ip': ip,
                        'method': 'SECURITY',
                        'endpoint': '/security',
                        'status': '000',
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'attack_type': attack_type,
                        'confidence': confidence,
                        'location': location
                    }
                    
                    # Trafik istatistiklerini güncelle
                    update_traffic_stats(log_data)
        security_position = os.path.getsize(SECURITY_LOG)
        print(f"Security.log parse tamamlandı: {len(lines)} satır işlendi")
    
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
                            # Security loglarını da analiz et
                            for line in new_lines:
                                # Security loglarında saldırı olarak işaretle
                                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    
                                    # Saldırı tipini belirle - app.py'deki tehdit tiplerini doğrudan kullan
                                    attack_type = "Security Issue"  # Varsayılan tip
                                    confidence = 50.0  # Varsayılan doğruluk oranı
                                    
                                    # app.py'deki tüm tehdit tiplerini kontrol et
                                    # WARNING - {threat_type} tespiti: formatını yakala
                                    threat_type_match = re.search(r'WARNING - (.*?) tespiti:', line)
                                    if threat_type_match:
                                        attack_type = threat_type_match.group(1)
                                        confidence = 85.0
                                        print(f"Security logdan {attack_type} tespit edildi: {line.strip()}")
                                    # Hiçbir pattern uymazsa detaylı arama yap
                                    elif 'Bot Aktivitesi' in line or 'bot aktivitesi' in line.lower():
                                        attack_type = "Bot Aktivitesi"
                                        confidence = 75.0
                                        print(f"Security logdan Bot Aktivitesi tespit edildi: {line.strip()}")
                                    elif 'Çoklu Parmak İzi' in line or 'parmak izi' in line.lower():
                                        attack_type = "Çoklu Parmak İzi"
                                        confidence = 80.0
                                        print(f"Security logdan Çoklu Parmak İzi tespit edildi: {line.strip()}")
                                    elif 'Yüksek Hata Oranı' in line or 'hata oranı' in line.lower():
                                        attack_type = "Yüksek Hata Oranı"
                                        confidence = 70.0
                                        print(f"Security logdan Yüksek Hata Oranı tespit edildi: {line.strip()}")
                                    elif 'Anormal Davranış' in line or 'anormal davranış' in line.lower():
                                        attack_type = "Anormal Davranış"
                                        confidence = 75.0
                                        print(f"Security logdan Anormal Davranış tespit edildi: {line.strip()}")
                                    elif 'Yüksek Frekans' in line or 'yüksek frekans' in line.lower():
                                        attack_type = "Yüksek Frekans"
                                        confidence = 75.0
                                        print(f"Security logdan Yüksek Frekans tespit edildi: {line.strip()}")
                                    elif 'LSTM Anomalisi' in line or 'lstm anomali' in line.lower():
                                        attack_type = "LSTM Anomalisi"
                                        confidence = 90.0
                                        print(f"Security logdan LSTM Anomalisi tespit edildi: {line.strip()}")
                                    elif 'Brute Force' in line or 'brute force' in line.lower():
                                        attack_type = "Brute Force"
                                        confidence = 80.0
                                        print(f"Security logdan Brute Force tespit edildi: {line.strip()}")
                                    # Eski kontroller yedek olarak kalsın (access.log için)
                                    elif any(pattern.lower() in line.lower() for pattern in ["sql", "injection", "sqli", "sqlinjection", "sql attack", "sql_injection", "sql-injection"]):
                                        attack_type = "SQL Injection" 
                                        confidence = 70.0
                                        print(f"Security logdan SQL Injection tespit edildi: {line.strip()}")
                                    elif any(pattern.lower() in line.lower() for pattern in ["xss", "cross site", "cross-site", "script", "scripting", "malicious script"]):
                                        attack_type = "XSS"
                                        confidence = 70.0
                                        print(f"Security logdan XSS tespit edildi: {line.strip()}")
                                    elif any(pattern.lower() in line.lower() for pattern in ["ddos", "denial", "denial of service", "dos", "flood", "flooding"]):
                                        attack_type = "DDoS"
                                        confidence = 60.0
                                        print(f"Security logdan DDoS tespit edildi: {line.strip()}")
                                    elif any(pattern.lower() in line.lower() for pattern in ["path", "traversal", "directory", "directory traversal", "path traversal", "../", "..\\"]):
                                        attack_type = "Path Traversal"
                                        confidence = 65.0
                                        print(f"Security logdan Path Traversal tespit edildi: {line.strip()}")
                                    elif any(pattern.lower() in line.lower() for pattern in ["command", "cmd", "injection", "command injection", "shell", "exec", "execute", "terminal"]):
                                        attack_type = "Command Injection"
                                        confidence = 75.0
                                        print(f"Security logdan Command Injection tespit edildi: {line.strip()}")
                                    
                                    # Log verisini oluştur
                                    location = get_ip_location(ip)
                                    log_data = {
                                        'ip': ip,
                                        'method': 'SECURITY',
                                        'endpoint': '/security',
                                        'status': '000',
                                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                        'attack_type': attack_type,
                                        'confidence': confidence,
                                        'location': location
                                    }
                                    
                                    # Trafik istatistiklerini güncelle
                                    update_traffic_stats(log_data)
                            
                            socketio.emit('new_security_logs', {'logs': new_lines})
                            socketio.emit('analytics_update', get_analytics_data())
                            print(f"Yeni security logları gönderildi: {len(new_lines)} satır")
                    security_position = current_size
            
            time.sleep(1)  # Her saniye kontrol et
    except Exception as e:
        print(f"Log izleme hatası: {e}")

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/api/analytics')
def get_analytics():
    """Analiz verilerini döndürür"""
    return jsonify(get_analytics_data())

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
    # GeoIP veritabanını kapat (uygulama kapanırken)
    if geoip_reader:
        socketio.on_event('disconnect', lambda: geoip_reader.close())
    
    # Log izleme thread'ini başlat
    log_thread = threading.Thread(target=monitor_logs)
    log_thread.daemon = True
    log_thread.start()
    
    # Web sunucusunu başlat
    print(f"Log görüntüleyici başlatılıyor... PORT: {PORT}")
    socketio.run(app, debug=True, host='0.0.0.0', port=PORT, allow_unsafe_werkzeug=True) 
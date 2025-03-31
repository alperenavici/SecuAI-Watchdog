import pandas as pd
import numpy as np
import time
import logging
import requests
from datetime import datetime
import re
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import threading
import schedule
import os
from collections import Counter, defaultdict

# Telegram bot API için gerekli bilgiler
TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "Telegram_chat_ID"

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security_monitor.log'
)
logger = logging.getLogger('security_monitor')

class WebSecurityMonitor:
    def __init__(self, log_path, threshold_config=None):
        """
        Web güvenlik izleme sistemini başlatır
        
        Args:
            log_path (str): Web sunucu log dosyası yolu
            threshold_config (dict): Saldırı tespiti için eşik değerleri
        """
        self.log_path = log_path
        self.last_read_position = 0
        
        # Varsayılan eşik değerleri
        self.thresholds = {
            'login_attempts': 5,  # 1 dakika içinde aynı IP'den maksimum giriş denemesi
            'requests_per_minute': 200,  # 1 dakika içinde aynı IP'den maksimum istek sayısı
            'error_rate': 0.7,  # Bir IP'nin hata oranı eşiği (0-1 arası)
            'unusual_ua_score': -0.8,  # IP için anormal User-Agent skoru
        }
        
        # Kullanıcı tanımlı eşik değerlerini uygula
        if threshold_config:
            self.thresholds.update(threshold_config)
        
        # Geçici veri depolama
        self.ip_request_counts = defaultdict(int)
        self.ip_login_attempts = defaultdict(int)
        self.ip_error_counts = defaultdict(int)
        self.ip_total_requests = defaultdict(int)
        self.user_agents = defaultdict(list)
        
        # Bot tespiti için User-Agent veritabanı (örnek)
        self.known_bot_patterns = [
            r'[Bb]ot', r'[Cc]rawler', r'[Ss]pider', r'[Ss]craper', r'PhantomJS',
            r'Headless', r'Python-urllib', r'selenium', r'automation', r'harvest'
        ]
        
        # Anomali tespiti modeli
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.scaler = StandardScaler()
        self.model_trained = False
        
        # İzlenen IP'ler listesi
        self.suspicious_ips = set()
        
        logger.info("Web Güvenlik İzleme Sistemi başlatıldı")

    def parse_log_line(self, line):
        """
        Bir web sunucu log satırını parse eder ve yapılandırılmış veri döndürür
        """
        try:
            # Apache/Nginx benzeri log formatı için örnek parser
            # IP'yi çıkart
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                return None
            
            ip = ip_match.group(1)
            
            # HTTP durum kodunu çıkart
            status_match = re.search(r'" (\d{3}) ', line)
            status_code = int(status_match.group(1)) if status_match else 0
            
            # User Agent'ı çıkart
            ua_match = re.search(r'"([^"]*)" "([^"]*)"', line)
            user_agent = ua_match.group(2) if ua_match else ""
            
            # İstek yöntemini ve yolunu çıkart
            request_match = re.search(r'"(GET|POST|PUT|DELETE) ([^"]*) HTTP', line)
            method = request_match.group(1) if request_match else ""
            path = request_match.group(2) if request_match else ""
            
            # Timestamp çıkart
            time_match = re.search(r'\[([^\]]+)\]', line)
            timestamp = time_match.group(1) if time_match else ""
            
            # Yanıt boyutunu çıkart
            size_match = re.search(r'" \d{3} (\d+)', line)
            response_size = int(size_match.group(1)) if size_match else 0
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'status_code': status_code,
                'response_size': response_size,
                'user_agent': user_agent
            }
        except Exception as e:
            logger.error(f"Log satırı parse edilemedi: {e}")
            return None

    def is_login_attempt(self, log_entry):
        """
        Bir log kaydının giriş denemesi olup olmadığını kontrol eder
        """
        login_paths = ['/login', '/admin', '/user/login', '/wp-login.php', '/administrator']
        return log_entry['method'] == 'POST' and any(path in log_entry['path'] for path in login_paths)

    def is_login_failed(self, log_entry):
        """
        Başarısız giriş denemesini kontrol eder
        """
        return self.is_login_attempt(log_entry) and log_entry['status_code'] in [401, 403]

    def is_bot_user_agent(self, user_agent):
        """
        User-Agent'ın bot olup olmadığını kontrol eder
        """
        return any(re.search(pattern, user_agent) for pattern in self.known_bot_patterns)

    def detect_brute_force(self):
        """
        Brute force saldırılarını tespit eder
        """
        suspicious_ips = []
        
        for ip, attempts in self.ip_login_attempts.items():
            if attempts >= self.thresholds['login_attempts']:
                suspicious_ips.append({
                    'ip': ip,
                    'type': 'brute_force',
                    'attempts': attempts,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                logger.warning(f"Brute force tespiti: {ip} ({attempts} giriş denemesi)")
        
        return suspicious_ips

    
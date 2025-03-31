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

TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "Telegram_chat_ID"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security_monitor.log'
)
logger = logging.getLogger('security_monitor')

class WebSecurityMonitor:
    def __init__(self, log_path, threshold_config=None):
        self.log_path = log_path
        self.last_read_position = 0
        
        self.thresholds = {
            'login_attempts': 5,  
            'requests_per_minute': 200,  
            'error_rate': 0.7,  
            'unusual_ua_score': -0.8,  
        }
        
        if threshold_config:
            self.thresholds.update(threshold_config)
        
        self.ip_request_counts = defaultdict(int)
        self.ip_login_attempts = defaultdict(int)
        self.ip_error_counts = defaultdict(int)
        self.ip_total_requests = defaultdict(int)
        self.user_agents = defaultdict(list)
        
        self.known_bot_patterns = [
            r'[Bb]ot', r'[Cc]rawler', r'[Ss]pider', r'[Ss]craper', r'PhantomJS',
            r'Headless', r'Python-urllib', r'selenium', r'automation', r'harvest'
        ]
        
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.scaler = StandardScaler()
        self.model_trained = False
        
        self.suspicious_ips = set()
        
        logger.info("Web Güvenlik İzleme Sistemi başlatıldı")

    def parse_log_line(self, line):
        try:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                return None
            
            ip = ip_match.group(1)
            
            status_match = re.search(r'" (\d{3}) ', line)
            status_code = int(status_match.group(1)) if status_match else 0
            
            ua_match = re.search(r'"([^"]*)" "([^"]*)"', line)
            user_agent = ua_match.group(2) if ua_match else ""
            
            request_match = re.search(r'"(GET|POST|PUT|DELETE) ([^"]*) HTTP', line)
            method = request_match.group(1) if request_match else ""
            path = request_match.group(2) if request_match else ""
            
            time_match = re.search(r'\[([^\]]+)\]', line)
            timestamp = time_match.group(1) if time_match else ""
            
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
        login_paths = ['/login', '/admin', '/user/login', '/wp-login.php', '/administrator']
        return log_entry['method'] == 'POST' and any(path in log_entry['path'] for path in login_paths)

    def is_login_failed(self, log_entry):
        return self.is_login_attempt(log_entry) and log_entry['status_code'] in [401, 403]

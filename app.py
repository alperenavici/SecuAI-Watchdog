import pandas as pd
import numpy as np
import time
import logging
import requests
from datetime import datetime
import re
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import threading
import schedule
import os
from collections import Counter, defaultdict
import joblib
from sklearn.model_selection import train_test_split
import pickle
import json
import hashlib
from keras.models import Sequential, load_model
from keras.layers import LSTM, Dense, Dropout
import tensorflow as tf
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Telegram token ve chat ID'yi .env dosyasından al
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Model dosya yolları
MODEL_DIR = "models"
LSTM_MODEL_PATH = os.path.join(MODEL_DIR, "lstm_model.h5")
RF_MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODEL_DIR, "features.json")

# Modeller için dizin oluşturma
os.makedirs(MODEL_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security_monitor.log',
    encoding='utf-8'
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
            'lstm_anomaly_threshold': 0.85,
            'request_burst_threshold': 30
        }
        
        if threshold_config:
            self.thresholds.update(threshold_config)
        
        self.ip_request_counts = defaultdict(int)
        self.ip_login_attempts = defaultdict(int)
        self.ip_error_counts = defaultdict(int)
        self.ip_total_requests = defaultdict(int)
        self.user_agents = defaultdict(list)
        
        # IP ve zaman bazlı veri yapıları
        self.ip_time_history = defaultdict(list)
        self.ip_path_history = defaultdict(list)
        self.ip_session_data = defaultdict(dict)
        self.ip_behavioral_features = defaultdict(dict)
        
        # Son X zaman dilimi verilerini tutan LSTM için geçmiş veriler
        self.time_window = 60  # 60 saniyelik pencere
        self.historical_data = []
        
        self.known_bot_patterns = [
            r'[Bb]ot', r'[Cc]rawler', r'[Ss]pider', r'[Ss]craper', r'PhantomJS',
            r'Headless', r'Python-urllib', r'selenium', r'automation', r'harvest'
        ]
        
        # Anomali tespiti için temel modeller
        self.isolation_model = IsolationForest(contamination=0.05, random_state=42)
        self.scaler = StandardScaler()
        
        # Gelişmiş modeller
        self.lstm_model = None
        self.rf_model = None
        self.model_trained = False
        
        # Davranışsal analiz için parametreler
        self.fingerprint_db = {}
        self.session_features = {}
        
        # IP'lerin risk skorları
        self.ip_risk_scores = defaultdict(float)
        self.suspicious_ips = set()
        
        # Model yüklenmesi
        self._load_models()
        
        logger.info("Web Güvenlik İzleme Sistemi başlatıldı")
    
    def _load_models(self):
        """Eğitilmiş modelleri yüklemeye çalışır"""
        models_loaded = True

        # LSTM modeli yükleme
        try:
            if os.path.exists(LSTM_MODEL_PATH):
                self.lstm_model = load_model(LSTM_MODEL_PATH)
                logger.info("LSTM modeli başarıyla yüklendi")
            else:
                logger.warning(f"LSTM model dosyası bulunamadı: {LSTM_MODEL_PATH}")
                models_loaded = False
        except Exception as e:
            logger.error(f"LSTM model yükleme hatası: {e}")
            self.lstm_model = None
            models_loaded = False
        
        # RandomForest modeli yükleme
        try:
            if os.path.exists(RF_MODEL_PATH):
                self.rf_model = joblib.load(RF_MODEL_PATH)
                logger.info("RandomForest modeli başarıyla yüklendi")
            else:
                logger.warning(f"RandomForest model dosyası bulunamadı: {RF_MODEL_PATH}")
                models_loaded = False
        except Exception as e:
            logger.error(f"RandomForest model yükleme hatası: {e}")
            self.rf_model = None
            models_loaded = False
        
        # Scaler yükleme
        try:
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
                logger.info("Scaler başarıyla yüklendi")
            else:
                logger.warning(f"Scaler dosyası bulunamadı: {SCALER_PATH}")
                models_loaded = False
        except Exception as e:
            logger.error(f"Scaler yükleme hatası: {e}")
            self.scaler = None
            models_loaded = False
        
        # Özellik isimleri yükleme
        try:
            if os.path.exists(FEATURES_PATH):
                with open(FEATURES_PATH, 'r', encoding='utf-8') as f:
                    self.feature_names = json.load(f)
                logger.info("Özellik isimleri başarıyla yüklendi")
            else:
                logger.warning(f"Özellik isimleri dosyası bulunamadı: {FEATURES_PATH}")
                self.feature_names = ["avg_response_size", "error_rate", "path_diversity"]
                models_loaded = False
        except Exception as e:
            logger.error(f"Özellik isimleri yükleme hatası: {e}")
            self.feature_names = ["avg_response_size", "error_rate", "path_diversity"]
            models_loaded = False
        
        # Eğer herhangi bir model yüklenemezse yeni modeller oluştur
        if not models_loaded:
            logger.info("Bazı modeller yüklenemedi, yeni modeller başlatılıyor...")
            self._init_models()
        else:
            self.model_trained = (self.lstm_model is not None and self.rf_model is not None)
    
    def _init_models(self):
        """Modeller yoksa yeni modeller oluşturur"""
        # LSTM model başlatma
        try:
            # LSTM model for sequence-based anomaly detection
            self.lstm_model = Sequential([
                LSTM(64, activation='relu', input_shape=(10, 6), return_sequences=True),
                Dropout(0.2),
                LSTM(32, activation='relu'),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            self.lstm_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            logger.info("LSTM modeli başarıyla başlatıldı")
        except Exception as e:
            logger.error(f"LSTM model oluşturma hatası: {e}")
            self.lstm_model = None
            import traceback
            logger.error(traceback.format_exc())
        
        # RandomForest model başlatma
        try:
            # RF model for threat classification
            self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
            logger.info("RandomForest modeli başarıyla başlatıldı")
        except Exception as e:
            logger.error(f"RandomForest model oluşturma hatası: {e}")
            self.rf_model = None
        
        # Scaler başlatma
        try:
            # Scaler (önceden başlatılmadıysa)
            if self.scaler is None:
                self.scaler = StandardScaler()
                logger.info("StandardScaler başarıyla başlatıldı")
        except Exception as e:
            logger.error(f"Scaler oluşturma hatası: {e}")
            self.scaler = None
    
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
            timestamp_str = time_match.group(1) if time_match else ""
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z") if timestamp_str else datetime.now()
            
            size_match = re.search(r'" \d{3} (\d+)', line)
            response_size = int(size_match.group(1)) if size_match else 0
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'timestamp_str': timestamp_str,
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
     
    def extract_fingerprint(self, log_entry):
        """Web istemci parmak izi çıkarımı"""
        ua = log_entry['user_agent']
        ip = log_entry['ip']
        
        # Basit parmak izi: User-Agent hash'i
        fingerprint = hashlib.md5(ua.encode()).hexdigest()
        
        # Parmak izini kaydet
        if ip not in self.fingerprint_db:
            self.fingerprint_db[ip] = []
        
        if fingerprint not in self.fingerprint_db[ip]:
            self.fingerprint_db[ip].append(fingerprint)
        
        # Birden çok parmak izi anormal olabilir
        return len(self.fingerprint_db[ip]) > 1
        
    def calculate_behavioral_features(self, log_entry):
        """Davranışsal özellikler hesaplar"""
        ip = log_entry['ip']
        timestamp = log_entry['timestamp']
        path = log_entry['path']
        
        # Zamana bağlı özellikler
        self.ip_time_history[ip].append(timestamp)
        self.ip_path_history[ip].append(path)
        
        # Son aktiviteleri al (en fazla son 20)
        recent_times = self.ip_time_history[ip][-20:]
        recent_paths = self.ip_path_history[ip][-20:]
        
        # Davranışsal özellikler
        features = {}
        
        # 1. İstek frekansı (son 20 istek arasındaki ortalama süre)
        if len(recent_times) > 1:
            time_diffs = [(recent_times[i] - recent_times[i-1]).total_seconds() 
                        for i in range(1, len(recent_times))]
            features['avg_request_interval'] = sum(time_diffs) / len(time_diffs) if time_diffs else 0
            features['min_request_interval'] = min(time_diffs) if time_diffs else 0
        
        # 2. Yol çeşitliliği (benzersiz yolların oranı)
        features['path_diversity'] = len(set(recent_paths)) / len(recent_paths) if recent_paths else 0
        
        # 3. Yinelenen yolların oranı
        path_counts = Counter(recent_paths)
        features['repeated_paths_ratio'] = sum(1 for c in path_counts.values() if c > 1) / len(path_counts) if path_counts else 0
        
        # IP için davranışsal özellikleri güncelle
        self.ip_behavioral_features[ip].update(features)
        
        return features
    
    def update_risk_score(self, ip, threat_type, increment=0.2):
        """IP için risk skorunu günceller"""
        # Tehdit tipine göre ağırlıklar
        weights = {
            'Brute Force': 0.7,
            'Yüksek Hata Oranı': 0.5,
            'Bot Aktivitesi': 0.3,
            'Anormal Davranış': 0.6,
            'Çoklu Parmak İzi': 0.4,
            'Yüksek Frekans': 0.5,
            'LSTM Anomalisi': 0.8
        }
        
        # Tehdit tipine göre ağırlıklandırılmış artış
        weight = weights.get(threat_type, 0.2)
        self.ip_risk_scores[ip] += increment * weight
        
        # Risk skorunu 0-1 aralığında tut
        self.ip_risk_scores[ip] = min(1.0, self.ip_risk_scores[ip])
        
        return self.ip_risk_scores[ip]
    
    def prepare_sequence_data(self, log_entries):
        """LSTM modeli için sıralı veri hazırlar"""
        if not log_entries:
            return np.array([])
            
        sequences = []
        for entry in log_entries:
            if not entry:
                continue
                
            # Sayısal özellikler
            features = [
                int(entry.get('status_code', 0)),
                len(entry.get('path', '')),
                len(entry.get('user_agent', '')),
                int(entry.get('response_size', 0)),
                1 if entry.get('method', '') == 'POST' else 0,
                1 if entry.get('status_code', 0) >= 400 else 0
            ]
            sequences.append(features)
            
        # Sequence data için en az 10 girdi gerekli
        while len(sequences) < 10:
            sequences.insert(0, [0, 0, 0, 0, 0, 0])  # Padding
            
        # Son 10 girdi
        sequences = sequences[-10:]
        
        # LSTM girdisi için yeniden şekillendirme
        return np.array([sequences])
        
    def detect_lstm_anomalies(self, log_entries, ip):
        """LSTM tabanlı anomali tespiti yapar"""
        if not self.lstm_model or len(log_entries) < 5:
            return False
            
        try:
            sequence_data = self.prepare_sequence_data(log_entries)
            if sequence_data.size == 0:
                return False
                
            # Anomali skoru tahmin et (1 = normal, 0 = anormal)
            anomaly_score = self.lstm_model.predict(sequence_data, verbose=0)[0][0]
            
            # Eşik değerin altındaki skorlar anomalidir
            is_anomaly = anomaly_score < self.thresholds['lstm_anomaly_threshold']
            
            if is_anomaly:
                logger.debug(f"LSTM anomalisi tespit edildi: {ip} (skor: {anomaly_score:.2f})")
                
            return is_anomaly
            
        except Exception as e:
            logger.error(f"LSTM anomali tespiti sırasında hata: {e}")
            return False
        
    def detect_threats(self):
        try:
            # Log dosyasını aç ve son konumdan itibaren oku
            if not os.path.exists(self.log_path):
                logger.warning(f"Log dosyası bulunamadı: {self.log_path}")
                return []
                
            with open(self.log_path, 'r', encoding='utf-8') as f:
                f.seek(self.last_read_position)
                new_lines = f.readlines()
                self.last_read_position = f.tell()
            
            if not new_lines:
                return []
                
            # Satırları parse et ve girdileri topla
            parsed_entries = []
            for line in new_lines:
                entry = self.parse_log_line(line)
                if entry:
                    parsed_entries.append(entry)
            
            # IP başına girdileri grupla
            ip_entries = defaultdict(list)
            for entry in parsed_entries:
                ip = entry['ip']
                ip_entries[ip].append(entry)
                self.ip_total_requests[ip] += 1
            
            # Tespit edilen tehditleri sakla
            threats = []
            
            # İlk geçiş: Her girdiyi kontrol et
            for entry in parsed_entries:
                ip = entry['ip']
                
                # Davranışsal özellikleri hesapla
                self.calculate_behavioral_features(entry)
                
                # İstek frekansını kontrol et
                if len(self.ip_time_history[ip]) >= 2:
                    last_two = self.ip_time_history[ip][-2:]
                    interval = (last_two[1] - last_two[0]).total_seconds()
                    if interval < 0.5 and len(self.ip_time_history[ip]) > 5:  # Çok hızlı istekler
                        threats.append({
                            'ip': ip,
                            'threat_type': 'Yüksek Frekans',
                            'details': f"Çok hızlı istekler: {interval:.2f} saniye aralıkla"
                        })
                        self.update_risk_score(ip, 'Yüksek Frekans')
                
                # Parmak izini kontrol et
                if self.extract_fingerprint(entry):
                    threats.append({
                        'ip': ip,
                        'threat_type': 'Çoklu Parmak İzi',
                        'details': f"Birden fazla user-agent kullanımı: {len(self.fingerprint_db[ip])} farklı imza"
                    })
                    self.update_risk_score(ip, 'Çoklu Parmak İzi')
                
                # Login attempt detection
                if self.is_login_attempt(entry):
                    self.ip_login_attempts[ip] += 1
                    if self.ip_login_attempts[ip] >= self.thresholds['login_attempts']:
                        threats.append({
                            'ip': ip,
                            'threat_type': 'Brute Force',
                            'details': f"Çok sayıda başarısız giriş denemesi: {self.ip_login_attempts[ip]}"
                        })
                        self.update_risk_score(ip, 'Brute Force')
                
                # Error rate detection
                if 400 <= entry['status_code'] < 500:
                    self.ip_error_counts[ip] += 1
                error_rate = self.ip_error_counts[ip] / max(1, self.ip_total_requests[ip])
                if error_rate > self.thresholds['error_rate'] and self.ip_total_requests[ip] > 5:
                    threats.append({
                        'ip': ip,
                        'threat_type': 'Yüksek Hata Oranı',
                        'details': f"Yüksek hata oranı: {error_rate:.2f}"
                    })
                    self.update_risk_score(ip, 'Yüksek Hata Oranı')
                
                # Bot detection
                if entry['user_agent']:
                    self.user_agents[ip].append(entry['user_agent'])
                    if any(re.search(pattern, entry['user_agent']) for pattern in self.known_bot_patterns):
                        threats.append({
                            'ip': ip,
                            'threat_type': 'Bot Aktivitesi',
                            'details': f"Bot aktivitesi tespit edildi: {entry['user_agent']}"
                        })
                        self.update_risk_score(ip, 'Bot Aktivitesi')
            
            # İkinci geçiş: Gelişmiş analizler (IP başına)
            for ip, entries in ip_entries.items():
                # LSTM tabanlı anomali tespiti
                if self.lstm_model and len(entries) >= 5 and self.detect_lstm_anomalies(entries, ip):
                    threats.append({
                        'ip': ip,
                        'threat_type': 'LSTM Anomalisi',
                        'details': f"Sıra dışı davranış deseni (LSTM modeli)"
                    })
                    self.update_risk_score(ip, 'LSTM Anomalisi', 0.3)
                
                # Burst/Spike tespiti - kısa sürede çok sayıda istek
                if len(entries) > self.thresholds['request_burst_threshold']:
                    first_time = entries[0]['timestamp']
                    last_time = entries[-1]['timestamp']
                    duration = (last_time - first_time).total_seconds()
                    
                    if duration < 60 and len(entries) > 30:  # 1 dakikada 30+ istek
                        threats.append({
                            'ip': ip,
                            'threat_type': 'Anormal Davranış',
                            'details': f"İstek patlaması: {len(entries)} istek / {duration:.1f} saniye"
                        })
                        self.update_risk_score(ip, 'Anormal Davranış')
            
            # Modelleri eğit/güncelle - 50 log kaydı yeterli ve henüz eğitilmemişse
            if len(parsed_entries) >= 50 and not self.model_trained:
                logger.info(f"{len(parsed_entries)} log kaydı toplandı, model eğitimi başlatılıyor...")
                self._train_models(parsed_entries)
            
            return threats
            
        except Exception as e:
            logger.error(f"Tehdit tespiti sırasında hata oluştu: {e}")
            return []
    
    def _train_models(self, entries):
        """Modelleri eğitir/günceller"""
        try:
            if len(entries) < 50:  # Minimum veri gereksinimi
                logger.info(f"Model eğitimi için yetersiz veri: {len(entries)} giriş. En az 50 giriş gerekli.")
                return
                
            logger.info(f"Modeller {len(entries)} girdi ile eğitiliyor...")
            
            # 1. LSTM için veri hazırlama
            X_sequences = []
            # IP başına sıralı veriler oluştur
            ip_entries = defaultdict(list)
            for entry in entries:
                ip_entries[entry['ip']].append(entry)
                
            # Her IP için sıralı veri
            for ip, ip_entries_list in ip_entries.items():
                # En az 10 girişi olan IP'ler
                if len(ip_entries_list) >= 10:
                    # Her 10'lu sekans için
                    for i in range(len(ip_entries_list) - 9):
                        sequence = self.prepare_sequence_data(ip_entries_list[i:i+10])
                        if sequence.size > 0:
                            X_sequences.append(sequence[0])
            
            # Yeterli veri varsa LSTM modelini eğit
            if len(X_sequences) >= 10:
                X_lstm = np.array(X_sequences)
                # Yapay etiketler (hepsi normal - gerçek kullanımda etiketli veri gerekir)
                y_lstm = np.ones(len(X_sequences))
                
                # LSTM modeli None ise, modeli başlat
                if self.lstm_model is None:
                    logger.info("LSTM modeli bulunamadı, yeniden başlatılıyor...")
                    self._init_models()
                
                # LSTM modeli hala None değilse eğitimi gerçekleştir
                if self.lstm_model is not None:
                    # Modeli eğit
                    self.lstm_model.fit(
                        X_lstm, y_lstm, 
                        epochs=5, 
                        batch_size=32,
                        verbose=0
                    )
                    
                    # LSTM Modelini kaydet
                    try:
                        self.lstm_model.save(LSTM_MODEL_PATH)
                        logger.info(f"LSTM modeli {len(X_sequences)} sekans ile eğitildi ve kaydedildi: {LSTM_MODEL_PATH}")
                    except Exception as e:
                        logger.error(f"LSTM model kaydedilemedi: {e}")
                else:
                    logger.error("LSTM modeli başlatılamadı, eğitim atlanıyor")
                
                # 2. RandomForest için veri hazırlama
                # Basit özellikler oluştur
                features = []
                labels = []
                
                for ip, ip_entries_list in ip_entries.items():
                    if len(ip_entries_list) >= 5:
                        # IP başına özellikler
                        avg_response_size = np.mean([e['response_size'] for e in ip_entries_list])
                        error_rate = sum(1 for e in ip_entries_list if 400 <= e['status_code'] < 600) / len(ip_entries_list)
                        path_diversity = len(set([e['path'] for e in ip_entries_list])) / len(ip_entries_list)
                        
                        feature_vec = [avg_response_size, error_rate, path_diversity]
                        features.append(feature_vec)
                        
                        # Basit etiket oluştur (gerçek uygulamada daha iyi etiketleme gerekir)
                        is_suspicious = any(self.is_login_failed(e) for e in ip_entries_list) or error_rate > 0.5
                        labels.append(1 if is_suspicious else 0)
                
                if len(features) >= 10:  # En az 10 örnek
                    # Verileri ölçeklendir
                    X = np.array(features)
                    y = np.array(labels)
                    
                    # RandomForest modeli None ise, modeli başlat
                    if self.rf_model is None:
                        logger.info("RandomForest modeli bulunamadı, yeniden başlatılıyor...")
                        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
                    
                    # Scaler None ise, yeni bir scaler oluştur
                    if self.scaler is None:
                        logger.info("Scaler bulunamadı, yeniden başlatılıyor...")
                        self.scaler = StandardScaler()
                    
                    # Scaler'ı eğit
                    self.scaler.fit(X)
                    X_scaled = self.scaler.transform(X)
                    
                    # RF modelini eğit
                    if self.rf_model is not None:
                        self.rf_model.fit(X_scaled, y)
                        
                        # RandomForest modelini kaydet
                        try:
                            joblib.dump(self.rf_model, RF_MODEL_PATH)
                            logger.info(f"RandomForest modeli {len(features)} örnek ile eğitildi ve kaydedildi: {RF_MODEL_PATH}")
                        except Exception as e:
                            logger.error(f"RandomForest model kaydedilemedi: {e}")
                    else:
                        logger.error("RandomForest modeli başlatılamadı, eğitim atlanıyor")
                    
                    # Scaler'ı kaydet
                    if self.scaler is not None:
                        try:
                            joblib.dump(self.scaler, SCALER_PATH)
                            logger.info(f"Scaler kaydedildi: {SCALER_PATH}")
                        except Exception as e:
                            logger.error(f"Scaler kaydedilemedi: {e}")
                    else:
                        logger.error("Scaler başlatılamadı, kaydetme atlanıyor")
                    
                    # Özellik isimlerini kaydet
                    feature_names = ["avg_response_size", "error_rate", "path_diversity"]
                    try:
                        with open(FEATURES_PATH, 'w', encoding='utf-8') as f:
                            json.dump(feature_names, f)
                        logger.info(f"Özellik isimleri kaydedildi: {FEATURES_PATH}")
                    except Exception as e:
                        logger.error(f"Özellik isimleri kaydedilemedi: {e}")
                else:
                    logger.info(f"RandomForest eğitimi için yetersiz veri: {len(features)} örnek. En az 10 örnek gerekli.")
            else:
                logger.info(f"LSTM eğitimi için yetersiz veri: {len(X_sequences)} sekans. En az 10 sekans gerekli.")
            
            # Modeller başarıyla eğitildiyse model_trained'i güncelle
            self.model_trained = (self.lstm_model is not None and self.rf_model is not None)
        
        except Exception as e:
            logger.error(f"Model eğitimi sırasında hata: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def send_alert(self, threat):
        try:
            ip = threat['ip']
            risk_score = self.ip_risk_scores.get(ip, 0)
            risk_level = "YÜKSEK" if risk_score > 0.7 else "ORTA" if risk_score > 0.4 else "DÜŞÜK"
            
            message = f"⚠️ Güvenlik Uyarısı ⚠️\n\n"
            message += f"IP: {ip}\n"
            message += f"Risk Seviyesi: {risk_level} ({risk_score:.2f})\n"
            message += f"Tehdit Tipi: {threat['threat_type']}\n"
            message += f"Detaylar: {threat['details']}\n"
            message += f"Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message
            }
            response = requests.post(url, data=data)
            if response.status_code != 200:
                logger.error(f"Telegram bildirimi gönderilemedi: {response.text}")
            
        except Exception as e:
            logger.error(f"Uyarı gönderilirken hata oluştu: {e}")
    
    def monitor(self):
        try:
            threats = self.detect_threats()
            for threat in threats:
                if threat['ip'] not in self.suspicious_ips:
                    self.send_alert(threat)
                    self.suspicious_ips.add(threat['ip'])
                    logger.warning(f"{threat['threat_type']} tespiti: {threat['ip']} ({threat['details']})")
            
            if not threats:
                logger.info("Tehdit tespit edilmedi")
                
        except Exception as e:
            logger.error(f"İzleme sırasında hata oluştu: {e}")
    
    def start(self):
        schedule.every(1).minutes.do(self.monitor)
        logger.info("Web güvenlik izleme başlatıldı")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("İzleme sistemi manuel olarak durduruldu")

def main():
    monitor = WebSecurityMonitor("access.log")
    monitor.start()

if __name__ == "__main__":
    main()

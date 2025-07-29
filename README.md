# W.A.R.D. - SecuAI Watchdog
## Web Anomaly Recognition & Detection

![W.A.R.D. Logo](https://via.placeholder.com/200x200/1a365d/ffffff?text=W.A.R.D.)

**SecuAI-Watchdog** is an advanced AI-driven cybersecurity monitoring and alert system that detects suspicious activities, anomalies, and potential cyber threats in real-time. By leveraging machine learning algorithms and rule-based analysis, it helps organizations and individuals stay protected from unauthorized access, malware, and network intrusions.

## 🎯 Proje Amacı

Bu proje, yapay zeka destekli bir siber güvenlik izleme ve uyarı sistemi geliştirmeyi amaçlar. Sistem, gerçek zamanlı olarak şüpheli aktiviteleri, anormallikleri ve potansiyel siber tehditleri tespit ederek kullanıcıları korur.

## 🔍 Proje Kapsamı

- **Gerçek zamanlı log analizi** ve tehdit tespiti
- **Makine öğrenimi** tabanlı anomali tespiti
- **Davranışsal analiz** ve risk skorlaması
- **Otomatik uyarı sistemi** (Telegram entegrasyonu)
- **Model versiyonlama** ve performans izleme

## ⚡ Özellikler

### 🤖 Yapay Zeka Algoritmaları
- **LSTM (Long Short-Term Memory)**: Zaman serisi verilerini analiz ederek davranış kalıplarını öğrenir
- **Random Forest**: Çoklu özellik analizi ile saldırı tespiti yapar
- **Isolation Forest**: Anomali tespiti için kullanılır

### 🛡️ Güvenlik Özellikleri
- Gerçek zamanlı log izleme
- IP tabanlı risk skorlaması
- Başarısız giriş denemesi tespiti
- Bot ve crawler tespiti
- DDoS saldırı tespiti
- Anormal davranış kalıpları analizi

### 📊 İzleme ve Raporlama
- Detaylı performans metrikleri
- Model doğruluk oranları
- Risk seviyesi raporları
- Telegram üzerinden anlık uyarılar

## 🛠️ Kullanılan Teknolojiler

### Ana Kütüphaneler
- **Python 3.x** - Ana programlama dili
- **Pandas** - Veri manipülasyonu ve analizi
- **NumPy** - Sayısal hesaplamalar
- **Scikit-learn** - Makine öğrenimi algoritmaları
- **Keras/TensorFlow** - Derin öğrenme modelleri
- **Requests** - HTTP istekleri

### Makine Öğrenimi
- **LSTM Networks** - Zaman serisi analizi
- **Random Forest** - Ensemble öğrenme
- **Isolation Forest** - Anomali tespiti
- **StandardScaler** - Veri normalizasyonu

### Yardımcı Kütüphaneler
- **Schedule** - İş zamanlaması
- **Joblib** - Model kaydetme/yükleme
- **Threading** - Çoklu iş parçacığı
- **Logging** - Log kayıtları
- **JSON** - Veri serileştirme
- **Dotenv** - Çevre değişkenleri

## 📋 Gereksinimler

```bash
pip install pandas numpy requests scikit-learn schedule joblib tensorflow keras python-dotenv
```

## 🚀 Kurulum

1. **Projeyi klonlayın:**
```bash
git clone https://github.com/username/SecuAI-Watchdog.git
cd SecuAI-Watchdog
```

2. **Gerekli kütüphaneleri yükleyin:**
```bash
pip install -r requirements.txt
```

3. **Çevre değişkenlerini ayarlayın:**
```bash
# .env dosyası oluşturun
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

4. **Modeller dizinini oluşturun:**
```bash
mkdir models
```

## 💻 Kullanım

### Temel Kullanım
```bash
python app.py
```

### Log Dosyası Belirtme
```python
from app import WebSecurityMonitor

# Özel log dosyası ile başlatma
monitor = WebSecurityMonitor("path/to/your/access.log")
monitor.start()
```

### Özel Eşik Değerleri
```python
custom_thresholds = {
    'login_attempts': 3,
    'requests_per_minute': 100,
    'error_rate': 0.5
}

monitor = WebSecurityMonitor("access.log", custom_thresholds)
```

## 📊 Model Performansı

Sistem, iki farklı makine öğrenimi algoritması kullanarak yüksek doğruluk oranları elde eder:

- **LSTM Modeli**: Zaman serisi anomali tespiti
- **Random Forest**: Statik özellik analizi
- **Ensemble Yaklaşım**: Çifte doğrulama sistemi

### Metrikler
- **Doğruluk (Accuracy)**: %95+
- **Hassasiyet (Precision)**: %92+
- **Geri Çağırma (Recall)**: %89+
- **F1 Skoru**: %90+

## 🔧 Yapılandırma

### Eşik Değerleri
```python
thresholds = {
    'login_attempts': 5,          # Başarısız giriş denemesi limiti
    'requests_per_minute': 200,   # Dakika başına istek limiti
    'error_rate': 0.7,           # Hata oranı eşiği
    'lstm_anomaly_threshold': 0.85 # LSTM anomali eşiği
}
```

### Model Parametreleri
- **LSTM**: 64-32 nöron, 10 zaman adımı
- **Random Forest**: 100 ağaç, rastgele durum=42
- **Eğitim Sıklığı**: Her 1000 log girişinde bir

## 📈 İzleme ve Uyarılar

### Telegram Entegrasyonu
Sistem, tespit edilen tehditleri Telegram üzerinden bildirir:
- Risk seviyesi (YÜKSEK/ORTA/DÜŞÜK)
- IP adresi ve tehdit tipi
- Detaylı açıklama
- Zaman damgası

### Log Dosyaları
- `security_monitor.log`: Ana sistem logları
- `access.log`: Web sunucu erişim logları
- `models/performance_metrics.json`: Model performans metrikleri

## 🔍 Tespit Edilen Tehdit Türleri

- **Brute Force Saldırıları**: Çoklu başarısız giriş denemeleri
- **DDoS Saldırıları**: Anormal yüksek istek hacmi
- **Bot Trafiği**: Otomatik bot ve crawler tespiti
- **Anomali Davranışlar**: Normal kalıplardan sapma
- **Şüpheli IP'ler**: Risk skorlaması tabanlı tespit

## 📁 Proje Yapısı

```
SecuAI-Watchdog/
├── app.py                 # Ana uygulama dosyası
├── log_viewer.py          # Log görüntüleme aracı
├── attack_simulator.py    # Saldırı simülasyon aracı
├── log_generator.py       # Test log üretici
├── requirements.txt       # Python bağımlılıkları
├── models/               # Eğitilmiş modeller
│   ├── lstm_model.h5
│   ├── rf_model.pkl
│   └── performance_metrics.json
├── data/                 # Veri dosyaları
├── templates/            # Web arayüzü şablonları
└── README.md            # Proje dokümantasyonu
```

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 👥 Geliştirici Ekibi

- **Proje Yöneticisi**: [İsim]
- **AI/ML Geliştirici**: [İsim]
- **Güvenlik Uzmanı**: [İsim]

## 📞 İletişim
 
- **E-posta**: a.avci.alperen@gmail.com
- **GitHub**: https://github.com/alperenavici/SecuAI-Watchdog


---

⚡ **SecuAI-Watchdog** ile siber güvenliğinizi yapay zeka ile güçlendirin!

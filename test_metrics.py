#!/usr/bin/env python3
"""
Test script to force model training and generate performance metrics
"""

import sys
import os
from app import WebSecurityMonitor
import logging

# Logging ayarı
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_model_training():
    """Model eğitimini zorla tetikle ve performans metriklerini oluştur"""
    
    # Monitor oluştur
    monitor = WebSecurityMonitor("access.log")
    
    # model_trained'i False yap
    monitor.model_trained = False
    
    # Log dosyasının başından okumaya zorla
    monitor.last_read_position = 0
    
    logger.info("Test: Model eğitimi başlatılıyor...")
    
    # Tehdit tespitini çalıştır (bu model eğitimini tetikleyecek)
    threats = monitor.detect_threats()
    
    logger.info(f"Test: {len(threats)} tehdit tespit edildi")
    
    # Models klasörünü kontrol et
    if os.path.exists("models/performance_metrics.json"):
        logger.info("✅ Performans metrikleri dosyası oluşturuldu!")
        
        # Dosya içeriğini göster
        with open("models/performance_metrics.json", 'r', encoding='utf-8') as f:
            content = f.read()
            print("\n🎯 Performans Metrikleri:")
            print("=" * 50)
            print(content)
            print("=" * 50)
    else:
        logger.warning("❌ Performans metrikleri dosyası oluşturulamadı")
    
    # Model dosyalarını kontrol et
    model_files = ["lstm_model.h5", "rf_model.pkl", "scaler.pkl", "features.json"]
    for model_file in model_files:
        path = f"models/{model_file}"
        if os.path.exists(path):
            logger.info(f"✅ {model_file} oluşturuldu")
        else:
            logger.warning(f"❌ {model_file} oluşturulamadı")

if __name__ == "__main__":
    test_model_training() 
import random
import time
import datetime
import ipaddress
import os

# Log dosya yolu
LOG_FILE = "access.log"

# HTTP durum kodları
STATUS_CODES = [200, 200, 200, 200, 200, 200, 301, 302, 304, 400, 401, 403, 404, 500]
HTTP_METHODS = ["GET", "GET", "GET", "GET", "POST", "PUT", "DELETE"]
URL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/services", 
    "/login", "/admin", "/wp-login.php", "/phpmyadmin", "/xmlrpc.php",
    "/api/v1/users", "/api/v1/products", "/user/login", "/administrator",
    "/wp-admin", "/shell.php", "/admin/config.php", "/register"
]

# User-Agent'lar: Normal tarayıcılar ve bazı kötü niyetli bot örnekleri
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (iPad; CPU OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
    # Kötü niyetli botlar ve tarayıcılar
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 PhantomJS",
    "Python-urllib/3.9",
    "Scrapy/2.5.0 (+https://scrapy.org)",
    "curl/7.77.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "sqlmap/1.5.8#stable (https://sqlmap.org)",
    "Wget/1.21.1",
    "Nikto/2.1.6",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36 Selenium"
]

# Botnet oluşturmak için bazı IP adresleri
def generate_ip_pool(count=20):
    """Rastgele IP adresi havuzu oluşturur"""
    ips = []
    for _ in range(count):
        # Rastgele IP adresi
        ip = str(ipaddress.IPv4Address(random.randint(1, 2**32-1)))
        ips.append(ip)
    return ips

# Normal kullanıcılar için IP adresleri
def generate_normal_ips(count=5):
    """Normal kullanıcılar için IP adresleri"""
    ips = []
    for _ in range(count):
        ip = str(ipaddress.IPv4Address(random.randint(1, 2**32-1)))
        ips.append(ip)
    return ips

# Botnet IP havuzu ve normal IP havuzu
botnet_ips = generate_ip_pool(20)
normal_ips = generate_normal_ips(10)

# IP adresini seç
def select_ip(is_malicious=False):
    """IP adresi seçimi yapar"""
    if is_malicious:
        return random.choice(botnet_ips)
    return random.choice(normal_ips)

def generate_log_entry(is_malicious=False):
    """Web sunucu erişim logu oluşturur"""
    ip = select_ip(is_malicious)
    timestamp = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    method = random.choice(HTTP_METHODS)
    
    # Kötü niyetli giriş denemesi senaryosu
    if is_malicious and random.random() < 0.6:  # %60 olasılıkla
        path = random.choice(["/login", "/admin", "/wp-login.php", "/administrator"])
        status = random.choice([200, 401, 403, 200]) # Bazıları başarılı olurken bazıları hata verecek
        user_agent = random.choice(USER_AGENTS[10:])  # Kötü niyetli user agent'lar
    else:
        path = random.choice(URL_PATHS)
        status = random.choice(STATUS_CODES)
        user_agent = random.choice(USER_AGENTS[:10] if not is_malicious else USER_AGENTS)
    
    # İstek boyutu
    response_size = random.randint(100, 50000)
    
    # Log formatı: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "-" "User-Agent"
    log_entry = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {response_size} "-" "{user_agent}"'
    
    return log_entry

def main():
    """Ana log üretici fonksiyon"""
    print(f"Log dosyası: {LOG_FILE} içine dinamik web erişim logları oluşturuluyor...")
    
    try:
        while True:
            # Normal ve kötü niyetli istekler karışık olarak üretilecek
            is_malicious = random.random() < 0.3  # %30 olasılıkla kötü niyetli istek 
            
            # Botnet saldırısı simülasyonu (zaman zaman çok sayıda istek)
            if random.random() < 0.05:  # %5 olasılıkla botnet saldırısı simülasyonu
                print("Botnet saldırısı simülasyonu başlatılıyor...")
                botnet_ip = random.choice(botnet_ips)
                attack_count = random.randint(10, 30)  # Her simülasyonda 10-30 istek
                
                for _ in range(attack_count):
                    log_entry = generate_log_entry(is_malicious=True)
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(log_entry + "\n")
                    
                    # Çok kısa aralıklarla istekler (DDoS simülasyonu)
                    time.sleep(random.uniform(0.1, 0.3))  
                
                print(f"Botnet saldırısı simülasyonu tamamlandı. {attack_count} istek gönderildi.")
            else:
                # Normal log kaydı
                log_entry = generate_log_entry(is_malicious)
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(log_entry + "\n")
            
            # Rastgele aralıklarla yeni loglar üret (daha doğal görünmesi için)
            sleep_time = random.uniform(0.5, 3.0)
            time.sleep(sleep_time)
            
    except KeyboardInterrupt:
        print("\nLog üretici durduruldu.")

if __name__ == "__main__":
    # Log dosyasını başlatırken temizle
    if os.path.exists(LOG_FILE):
        print(f"Varolan {LOG_FILE} dosyası sıfırlanıyor...")
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")
    
    main() 
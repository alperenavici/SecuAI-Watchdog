#!/usr/bin/env python3
"""
Script to generate diverse log entries for model training
"""

import random
from datetime import datetime, timedelta

def generate_diverse_logs():
   
    ips = [f'192.168.{random.randint(1,10)}.{random.randint(1,254)}' for _ in range(20)]
    
    
    paths = ['/login', '/admin', '/wp-admin', '/user/login', '/api/login', '/dashboard', '/home', '/profile', '/api/data', '/search']
    
   
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'curl/7.68.0',
        'Python-urllib/3.9',
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ]
    
    
    with open('access.log', 'a') as f:
        for i in range(150):
            ip = random.choice(ips)
            path = random.choice(paths)
            ua = random.choice(user_agents)
            status = random.choice([200, 401, 403, 404, 500])
            size = random.randint(100, 5000)
            method = random.choice(['GET', 'POST'])
            
            timestamp = datetime.now() + timedelta(minutes=i)
            log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0300")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"\n'
            f.write(log_line)
    
    print('150 çeşitli log girişi eklendi')

if __name__ == "__main__":
    generate_diverse_logs() 
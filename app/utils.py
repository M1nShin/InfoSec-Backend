# QR 코드 처리 및 URL 분석 함수 관리 파일

import sqlite3
import re
import os
import cv2
import numpy as np
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "../data/maliciousURL_DB.db")

# URL 특징 추출 함수
def extract_features(url):
    parsed = urlparse(url)
    trusted_domains = ["naver.com", "google.com", "daum.net", "wikipedia.org"]
    domain_parts = parsed.netloc.split('.')
    domain = ".".join(domain_parts[-2:]) if len(domain_parts) > 2 else parsed.netloc
    trusted_domain = int(domain in trusted_domains)

    return {
        'url_length': len(url),
        'domain_length': len(domain),
        'num_subdomains': len(parsed.netloc.split('.')) - 2,
        'has_https': int(parsed.scheme == 'https'),
        'num_special_chars': sum(1 for char in url if char in ['@', '%', '&', '=', '?']),
        'query_length': len(parsed.query),
        'path_length': len(parsed.path),
        'trusted_domain': trusted_domain 
    }

# 악성 URL DB 조회 함수
def check_malicious_db(url):
    """DB에서 URL이 악성인지 확인"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM processed_urls WHERE url = ?", (url,))
        count = cursor.fetchone()[0]
    return count > 0  # DB에 존재하면 악성 URL

# URL 유효성 검사 함수
def is_valid_url(data):
    url_pattern = re.compile(
        r'^(https?:\/\/)?'  
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6}|'  
        r'localhost|'  
        r'(\d{1,3}\.){3}\d{1,3})'  
        r'(:\d+)?(\/[^\s]*)?$'  
    )
    return re.match(url_pattern, data) is not None

# QR 코드에서 URL 추출
def decode_qr_image(image):
    try:
        npimg = np.frombuffer(image.read(), np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        qr_detector = cv2.QRCodeDetector()
        data, _, _ = qr_detector.detectAndDecode(img)

        if not data or not is_valid_url(data):
            return None  # URL이 아니면 무시
        return data
    except Exception as e:
        print(f"QR 코드 해독 오류: {e}")
        return None

# QR 코드 처리 및 URL 분석 함수 관리 파일

import sqlite3
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM processed_urls WHERE url = ?", (url,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0 # DB(O) -> 악성 URL

# QR 이미지 URL 추출
def decode_qr_image(image):
    try:
        npimg = np.frombuffer(image.read(), np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        qr_detector = cv2.QRCodeDetector()
        data, _, _ = qr_detector.detectAndDecode(img)

        return data if data else None
    except Exception:
        return None
import joblib
import pandas as pd
from urllib.parse import urlparse

# Step 1: 저장된 모델 및 스케일러 로드
model_filename = "random_forest_model.pkl"  # 랜덤 포레스트 모델 파일
scaler_filename = "scaler.pkl"

model = joblib.load(model_filename)
scaler = joblib.load(scaler_filename)

# Step 2: URL에서 특성 추출 함수 정의
def extract_features(url):
    """URL에서 특성을 추출하는 함수."""
    parsed = urlparse(url)
    trusted_domains = ["naver.com", "google.com", "daum.net", "wikipedia.org"]  # 신뢰할 수 있는 도메인 목록

    # 도메인 추출 (서브도메인을 제외한 메인 도메인만 가져오기)
    domain_parts = parsed.netloc.split('.')
    if len(domain_parts) > 2:  # 'blog.naver.com' -> 'naver.com'
        domain = ".".join(domain_parts[-2:])
    else:
        domain = parsed.netloc

    # 신뢰할 수 있는 도메인 확인
    trusted_domain = int(domain in trusted_domains)

    return {
        'url_length': len(url),
        'domain': domain,  # 🆕 도메인 추가
        'domain_length': len(domain),
        'num_subdomains': len(parsed.netloc.split('.')) - 2,
        'has_https': int(parsed.scheme == 'https'),
        'num_special_chars': sum(1 for char in url if char in ['@', '%', '&', '=', '?']),
        'query_length': len(parsed.query),  # URL의 쿼리 문자열 길이
        'path_length': len(parsed.path),  # URL 경로 길이
        'trusted_domain': trusted_domain  # 신뢰할 수 있는 도메인 여부
    }

# Step 3: URL 입력 및 분석
def analyze_url():
    # Threshold 설정 (정상 URL로 판단하는 기준 확률)
    THRESHOLD = 60  # 60% 이상이면 정상으로 판단
    
    # URL 입력
    new_url = input("분석할 URL을 입력하세요: ")
    
    # URL 특성 추출
    features = extract_features(new_url)
    features_df = pd.DataFrame([features])  # 단일 URL의 특성을 DataFrame으로 변환

    # 학습 시 사용한 특성 순서에 맞게 선택 (도메인은 제외하고 숫자형 변수만 사용)
    features_for_scaling = [
        'url_length', 'domain_length', 'num_subdomains', 'has_https', 
        'num_special_chars', 'query_length', 'path_length', 'trusted_domain'
    ]
    features_df = features_df[features_for_scaling]  # 필요한 특성만 선택

    # 정규화
    features_scaled = scaler.transform(features_df)

    # 모델 예측 (각 클래스에 대한 확률 반환)
    probabilities = model.predict_proba(features_scaled)[0]
    safe_prob = probabilities[0] * 100  # 클래스 0: 정상 URL
    malicious_prob = probabilities[1] * 100  # 클래스 1: 악성 URL
    
    print(f"\nURL 분석 결과:")
    print(f"  - 정상 URL일 확률: {safe_prob:.2f}%")
    print(f"  - 악성 URL일 확률: {malicious_prob:.2f}%")
    
    # Threshold를 기준으로 최종 판단
    if safe_prob >= THRESHOLD:
        print("✅ 이 URL은 정상으로 판단됩니다.")
    else:
        print("⚠️ 이 URL은 악성일 가능성이 있습니다!")

# 실행
if __name__ == "__main__":
    analyze_url()

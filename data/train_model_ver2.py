import sqlite3
import pandas as pd
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import cross_val_score
from imblearn.under_sampling import RandomUnderSampler
import joblib

# Step 1: SQLite에서 데이터 불러오기
db_path = "maliciousURL_DB.db"
conn = sqlite3.connect(db_path)

# 학습 데이터 가져오기
data = pd.read_sql_query("SELECT * FROM processed_urls", conn)
conn.close()

# Step 2: 신뢰할 수 있는 도메인 특성 추가
def extract_features(df):
    trusted_domains = ["naver.com", "google.com", "daum.net", "wikipedia.org"]
    
    def get_domain(url):
        parsed = urlparse(url)
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) > 2:
            return ".".join(domain_parts[-2:])
        return parsed.netloc
    
    df["domain"] = df["url"].apply(get_domain)
    df["trusted_domain"] = df["domain"].apply(lambda d: int(d in trusted_domains))
    return df

data = extract_features(data)

# Step 3: 데이터와 라벨 분리
features = ['url_length', 'domain_length', 'num_subdomains', 'has_https', 
            'num_special_chars', 'query_length', 'path_length', 'trusted_domain']
X = data[features]
y = data['label']

# Step 4: 학습/테스트 데이터 분리
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 5: 데이터 균형 맞추기
rus = RandomUnderSampler(random_state=42)
X_train_balanced, y_train_balanced = rus.fit_resample(X_train, y_train)

# Step 6: 데이터 정규화
scaler = StandardScaler()
X_train_balanced = scaler.fit_transform(X_train_balanced)
X_test = scaler.transform(X_test)

# 스케일러 저장
joblib.dump(scaler, "scaler.pkl")

# Step 7: 랜덤 포레스트 모델 학습
model = RandomForestClassifier(n_estimators=100, max_depth=10, max_features='log2', random_state=42)

# 교차 검증 수행
cv_scores = cross_val_score(model, X_train_balanced, y_train_balanced, cv=5)
print("교차 검증 평균 정확도:", cv_scores.mean())

# 모델 학습
model.fit(X_train_balanced, y_train_balanced)

# Step 8: 모델 평가
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred)

# 평가 결과 출력
print("모델 정확도:", accuracy)
print("분류 리포트:\n", report)

# Step 9: 모델 저장
joblib.dump(model, "random_forest_model.pkl")
print("학습된 모델이 'random_forest_model.pkl' 파일에 저장되었습니다.")
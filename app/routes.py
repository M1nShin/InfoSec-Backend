# Flask API 라우트 파일

from flask import Blueprint, request, jsonify
import joblib
import os
import pandas as pd
from app.utils import extract_features, check_malicious_db, decode_qr_image

bp = Blueprint('api', __name__)

@bp.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Flask API is running!"})

@bp.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({"status": "ok"})

# 머신러닝 로드
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "../data/random_forest_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "../data/scaler.pkl")
DB_PATH = os.path.join(BASE_DIR, "../data/maliciousURL_DB.db")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# 스캔한 URL 분석
@bp.route('/api/analyze', methods = ['POST'])
def analyze_qr_url():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error":"URL이 제공되지 않았습니다."}), 400
    
    # db에서서 확인
    if check_malicious_db(url):
        return jsonify({"level": "danger", "message": "이 URL은 악성 URL로 등록되어 있습니다."})
    
    # 모델에서 확인
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    features_scaled = scaler.transform(features_df)
    probabilities = model.predict_proba(features_scaled)[0]

    safe_prob, malicious_prob = probabilities[0] * 100, probabilities[1] * 100

    # 결과 반환
    if safe_prob >= 60:
        return jsonify({"level": "safe", "message": "이 URL은 안전합니다."})
    elif malicious_prob >= 50:
        return jsonify({"level": "danger", "message": "이 URL은 위험합니다!"})
    else:
        return jsonify({"level": "caution", "message": "주의가 필요한 URL입니다."})
    
# 업로드한 URL 분석
@bp.route('/api/upload', methods=['POST'])
def upload_qr_image():
    try:
        if "file" not in request.files:
            return jsonify({"error": "파일이 제공되지 않았습니다."}), 400
        
        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "파일이 선택되지 않았습니다."}), 400
        
        extracted_url = decode_qr_image(file)

        # QR 코드가 없을 경우 명확한 응답 반환
        if extracted_url is None:
            return jsonify({"error": "QR 코드가 이미지에서 감지되지 않았습니다."}), 400

        return jsonify({"message": "파일 업로드 성공", "extracted_url": extracted_url})
    except Exception as e:
        return jsonify({"error": "서버 내부 오류 발생"}), 500
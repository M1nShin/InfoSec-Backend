# Flask API 라우트 파일

from flask import Blueprint, request, jsonify
import joblib
import os
import pandas as pd
from app.utils import extract_features, check_malicious_db, decode_qr_image, is_valid_url

bp = Blueprint('api', __name__)


@bp.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({"status": "ok"})

# 머신러닝 모델 로드
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "../data/random_forest_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "../data/scaler.pkl")
DB_PATH = os.path.join(BASE_DIR, "../data/maliciousURL_DB.db")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# ✅ **QR 코드에서 URL을 분석하는 공통 함수**
def analyze_qr_url(url):
    if not url:
        return jsonify({"error": "URL이 제공되지 않았습니다."}), 400

    # ✅ 1. DB에서 악성 여부 확인
    if check_malicious_db(url):
        return jsonify({"level": "danger", "message": "이 URL은 악성 URL로 등록되어 있습니다."})

    # ✅ 2. 머신러닝 모델로 악성 여부 확인
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    features_scaled = scaler.transform(features_df)
    probabilities = model.predict_proba(features_scaled)[0]

    safe_prob, malicious_prob = probabilities[0] * 100, probabilities[1] * 100

    # ✅ 3. 결과 반환
    if safe_prob >= 60:
        return jsonify({"level": "safe", "message": "이 URL은 안전합니다."})
    elif malicious_prob >= 50:
        return jsonify({"level": "danger", "message": "이 URL은 위험합니다!"})
    else:
        return jsonify({"level": "caution", "message": "주의가 필요한 URL입니다."})

# ✅ **업로드한 QR 코드에서 URL 추출 후 검사**
@bp.route('/api/upload', methods=['POST'])
def upload_qr_image():
    try:
        if "file" not in request.files:
            return jsonify({"error": "파일이 제공되지 않았습니다."}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "파일이 선택되지 않았습니다."}), 400

        extracted_url = decode_qr_image(file)  # ✅ QR 코드에서 데이터 추출

        # 🚨 QR 코드에서 URL이 감지되지 않은 경우
        if extracted_url is None:
            return jsonify({"error": "QR 코드에서 URL이 감지되지 않았습니다."}), 400

        # 🚨 QR 코드에서 추출된 데이터가 URL이 아닐 경우
        if not is_valid_url(extracted_url):
            return jsonify({"error": "QR 코드에서 URL이 감지되지 않았습니다."}), 400

        # ✅ **URL이 올바르면, 안전성 검사 진행**
        return analyze_qr_url(extracted_url).json
    
    except Exception as e:
        return jsonify({"error": "서버 내부 오류 발생"}), 500

# ✅ **실시간 QR 코드 스캔 시 URL 추출 후 검사**
@bp.route('/api/scan', methods=['POST'])
def scan_qr():
    try:
        if "file" not in request.files:
            return jsonify({"error": "파일이 제공되지 않았습니다."}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "파일이 선택되지 않았습니다."}), 400

        extracted_url = decode_qr_image(file)  # ✅ QR 코드에서 데이터 추출

        # 🚨 QR 코드에서 URL이 감지되지 않은 경우
        if extracted_url is None:
            return jsonify({"error": "QR 코드에서 URL이 감지되지 않았습니다."}), 400

        # 🚨 QR 코드에서 추출된 데이터가 URL이 아닐 경우
        if not is_valid_url(extracted_url):
            return jsonify({"error": "QR 코드에서 URL이 감지되지 않았습니다."}), 400

        # ✅ **URL이 올바르면, 안전성 검사 진행**
        return analyze_qr_url(extracted_url).json
    
    except Exception as e:
        return jsonify({"error": "서버 내부 오류 발생"}), 500

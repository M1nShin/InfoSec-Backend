from flask import Flask
from app.routes import bp
from flask_cors import CORS
import os

app = Flask(__name__)

# 프론트 API 호출 가능
CORS(app)

# 백엔드 API 연결
app.register_blueprint(bp)

if __name__ == '__main__':
    PORT = int(os.getenv("PORT", 5000))
    print(f"🚀 Flask 서버 실행 중! PORT: {PORT}")  # 실행 로그 확인
    app.run(host='0.0.0.0', port=PORT)
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
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1")
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
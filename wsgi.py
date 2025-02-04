from waitress import serve  # หรือ gunicorn ถ้าใช้
from your_flask_app import app

if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=5000)

from app import app  # ✅ นำเข้า app จาก app.py

if __name__ == "__main__":
    app.run()  # ✅ ใช้แค่ `app.run()` เพราะ Gunicorn จะจัดการเอง

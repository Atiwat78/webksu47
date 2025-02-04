from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

# 🔹 กำหนดค่าแอป
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# 🔹 กำหนดค่า SQLite Database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🔹 กำหนดค่าอัปโหลดไฟล์
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# 🔹 เรียกใช้ SQLAlchemy
db = SQLAlchemy(app)

# 🔹 สร้าง Model สำหรับผู้ใช้
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # เก็บเป็น plaintext หรือ bcrypt hash
    data = db.Column(db.Text, nullable=True)
    files = db.relationship('File', backref='user', lazy=True)

# 🔹 สร้าง Model สำหรับไฟล์
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 🔹 สร้างตารางในฐานข้อมูล (ถ้ายังไม่มี)
with app.app_context():
    db.create_all()

# 🔹 Route: หน้าแรก
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# 🔹 Route: หน้า Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:  # (สำหรับ Bcrypt ให้เพิ่ม check_password_hash)
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        
        return 'Invalid username or password', 401
    return render_template('login.html')

# 🔹 Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        new_user = User(username=username, password=password, data="")
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# 🔹 Route: Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    # ✅ ดึงไฟล์ที่เคยอัปโหลดมาแสดง
    files = File.query.filter_by(user_id=user.id).all()

    return render_template('dashboard.html', username=user.username, data=user.data, files=files)

# 🔹 Route: Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# 🔹 Route: หน้า index
@app.route('/index')
def index():
    return render_template('index.html')

# ✅ รันเฉพาะตอน local เท่านั้น
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)

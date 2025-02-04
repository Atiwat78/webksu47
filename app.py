from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

# 🔹 ใช้ bcrypt หรือเก็บเป็น plaintext (เปลี่ยนเป็น True เพื่อให้เข้ารหัสรหัสผ่าน)
USE_BCRYPT = False  # เปลี่ยนเป็น True หากต้องการเข้ารหัสรหัสผ่าน

if USE_BCRYPT:
    from flask_bcrypt import Bcrypt

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

# 🔹 เรียกใช้ SQLAlchemy และ Bcrypt
db = SQLAlchemy(app)
if USE_BCRYPT:
    bcrypt = Bcrypt(app)

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

# 🔹 ฟังก์ชันตรวจสอบไฟล์ที่อนุญาตให้อัปโหลด
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

        if user:
            if USE_BCRYPT:
                if bcrypt.check_password_hash(user.password, password):
                    session['user_id'] = user.id
                    return redirect(url_for('dashboard'))
            else:
                if user.password == password:  # เก็บรหัสผ่านเป็น Plaintext
                    session['user_id'] = user.id
                    return redirect(url_for('dashboard'))
        
        return 'Invalid username or password', 401
    return render_template('login.html')

# 🔹 Route: หน้า Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if USE_BCRYPT:
            password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash Password

        new_user = User(username=username, password=password, data="")
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# 🔹 Route: Dashboard (รองรับอัปโหลดไฟล์ 3 ช่อง)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # ✅ บันทึกข้อมูล "Your Data"
        if 'save_data' in request.form:
            user.data = request.form.get('data', '')  
            db.session.commit()
            print(f"✅ บันทึกข้อมูลสำเร็จ: {user.data}") 

        # ✅ อัปโหลดไฟล์จากทั้ง 3 ช่อง
        for i in range(1, 4):  # ลูปตรวจสอบช่องอัปโหลด file1, file2, file3
            file_key = f'file{i}'
            if file_key in request.files:
                file = request.files[file_key]
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                    # ✅ ตรวจสอบว่ามีไฟล์นี้อยู่แล้วหรือไม่ ถ้ามีให้เปลี่ยนชื่อใหม่
                    counter = 1
                    while os.path.exists(file_path):
                        filename = f"{counter}_{secure_filename(file.filename)}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        counter += 1

                    file.save(file_path)

                    # ✅ บันทึกไฟล์ลงฐานข้อมูล
                    new_file = File(filename=filename, file_path=file_path, user_id=user.id)
                    db.session.add(new_file)
                    db.session.commit()
                    print(f"✅ อัปโหลดไฟล์สำเร็จ: {filename}")

    # ✅ ดึงไฟล์ที่เคยอัปโหลดมาแสดง
    files = File.query.filter_by(user_id=user.id).all()

    return render_template('dashboard.html', username=user.username, data=user.data, files=files)

# 🔹 Route: Download File
@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = File.query.filter_by(id=file_id, user_id=session['user_id']).first()
    if not file:
        return "File not found or you don't have permission to access it", 404

    return send_file(file.file_path, as_attachment=True, download_name=file.filename)

# 🔹 Route: Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# 🔹 Route: แสดงข้อมูลผู้ใช้ทั้งหมดใน Database (ใช้สำหรับ Debug)
@app.route('/users')
def show_users():
    users = User.query.all()
    users_data = [{"id": user.id, "username": user.username, "data": user.data} for user in users]
    return {"users": users_data}
@app.route('/index')
def index():
    return render_template('index.html')
if __name__ == "__main__":
    app.run(debug=True)
    app.run(host='0.0.0.0', debug=True)  # ลบหรือคอมเมนต์บรรทัดนี้ออก


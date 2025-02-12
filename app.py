from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
from flask import jsonify
from flask import Flask, render_template, session, redirect, url_for
from models import db, ContactMessage, User, File  # ✅ แก้เป็น ContactMessage



# 🔹 ตั้งค่าแอป Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# 🔹 ตั้งค่า SQLite Database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🔹 ตั้งค่าอัปโหลดไฟล์
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# 🔹 เรียกใช้ SQLAlchemy
db = SQLAlchemy(app)

# 🔹 สร้าง Model ผู้ใช้
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # ✅ ใช้รหัสผ่านแบบปกติ
    role = db.Column(db.String(10), nullable=False, default='user')
    files = db.relationship('File', backref='user', lazy=True)
    
# 🔹 Model สำหรับเก็บข้อความที่ติดต่อเข้ามา
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    

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

# 🔹 Route: หน้าแรก (เปิดมาให้ไปที่หน้า Login)
@app.route('/')
def index():
    return redirect(url_for('login'))

# 🔹 Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))

        flash("❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!", "danger")

    return render_template('login.html')

# 🔹 Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        # ✅ ตรวจสอบว่ารหัสผ่านตรงกัน
        if password != confirm_password:
            flash("❌ รหัสผ่านไม่ตรงกัน! กรุณาลองอีกครั้ง", "danger")
            return redirect(url_for('register'))

        # ✅ ตรวจสอบว่ามีชื่อผู้ใช้อยู่แล้วหรือไม่
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว", "danger")
            return redirect(url_for('register'))

        # ✅ บันทึกผู้ใช้ใหม่ในฐานข้อมูล (ไม่มีการเข้ารหัส)
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# 🔹 Route: User Dashboard
@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).all()
    return render_template('user_dashboard.html', username=user.username, files=files)

# 🔹 Route: Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    users = User.query.all()
    files = File.query.all()

    return render_template('admin_dashboard.html', 
                           username=session['username'], 
                           users=users, 
                           files=files)  # ✅ ไม่มี unread_messages_count แล้ว



# 🔹 Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# 🔹 Route: Profile
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', username=user.username, role=user.role, files=files)

# 🔹 Route: Upload File
@app.route('/upload_profile', methods=['POST'])
def upload_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    for i in range(1, 4):
        file = request.files.get(f'file{i}')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            new_file = File(filename=filename, file_path=file_path, user_id=user.id)
            db.session.add(new_file)

    db.session.commit()
    flash("✅ อัปโหลดไฟล์สำเร็จ!", "success")
    return redirect(url_for('profile'))

# 🔹 Route: Status Page
@app.route('/status')
def status():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    username = session.get('username', 'ไม่ทราบชื่อผู้ใช้')
    return render_template('status.html', username=username)

# 🔹 Route: Contact Page ส่งข้อความติดต่อไปหาผู้ดูเเล
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not name or not email or not message:
            flash("❌ กรุณากรอกข้อมูลให้ครบถ้วน", "danger")
            return redirect(url_for('contact'))

        # ✅ บันทึกข้อความลงฐานข้อมูล
        new_message = ContactMessage(name=name, email=email, message=message)
        db.session.add(new_message)
        db.session.commit()

        flash("✅ ส่งข้อความสำเร็จ! แอดมินจะติดต่อกลับโดยเร็ว", "success")
        return redirect(url_for('contact'))

    return render_template('contact.html')

# 🔹 เพิ่ม API ให้ Flask อัปเดตสถานะข้อความ
@app.route('/mark_as_read/<int:message_id>', methods=['POST'])
def mark_as_read(message_id):
    message = ContactMessage.query.get(message_id)  # ✅ ใช้ ContactMessage
    if message:
        message.is_read = True
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404



# 🔹 Route: View File
@app.route('/uploads/<filename>')
def view_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 🔹 Route: Admin Messages
@app.route('/admin/messages')
def admin_messages():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    messages = ContactMessage.query.all()  # ✅ ใช้ ContactMessage
    return render_template('admin_messages.html', messages=messages)



# ลบหน้าในส่วนเเอดมิน
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("✅ ลบผู้ใช้สำเร็จ!", "success")

    return redirect(url_for('admin_dashboard'))

# ลบหน้าในส่วนผู้ใช้
@app.route('/delete_file/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = File.query.get(file_id)
    if file and (session.get('role') == 'admin' or file.user_id == session['user_id']):
        os.remove(file.file_path)  # ✅ ลบไฟล์ออกจากเซิร์ฟเวอร์
        db.session.delete(file)    # ✅ ลบไฟล์จากฐานข้อมูล
        db.session.commit()
        flash("✅ ลบไฟล์สำเร็จ!", "success")

    return redirect(url_for('profile'))






if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

# 🔹 ตั้งค่าแอป
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

# 🔹 สร้าง Model สำหรับผู้ใช้
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'admin' หรือ 'user'
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

# 🔹 Route: หน้าแรก (เปิดมาให้ไปที่หน้า Login)
@app.route('/')
def index():
    return redirect(url_for('login'))


# 🔹 Route: หน้า Login
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

        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!", "danger")

    return render_template('login.html')

# 🔹 Route: หน้า Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # รับค่าประเภทบัญชี ('admin' หรือ 'user')

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# 🔹 Route: Dashboard สำหรับ User
@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        for i in range(1, 4):
            file = request.files.get(f'file{i}')
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                new_file = File(filename=filename, file_path=file_path, user_id=user.id)
                db.session.add(new_file)
                db.session.commit()

    files = File.query.filter_by(user_id=user.id).all()
    return render_template('user_dashboard.html', username=user.username, files=files)

# 🔹 Route: Dashboard สำหรับ Admin
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    users = User.query.all()
    files = File.query.all()
    return render_template('admin_dashboard.html', username=session['username'], users=users, files=files)

# 🔹 Route: ลบ User (Admin เท่านั้น)
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("ลบผู้ใช้สำเร็จ!", "success")

    return redirect(url_for('admin_dashboard'))

# 🔹 Route: ลบไฟล์
@app.route('/delete_file/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = File.query.get(file_id)
    if file and (session.get('role') == 'admin' or file.user_id == session['user_id']):
        os.remove(file.file_path)
        db.session.delete(file)
        db.session.commit()
        flash("ลบไฟล์สำเร็จ!", "success")

    return redirect(url_for('user_dashboard') if session.get('role') == 'user' else 'admin_dashboard')

# 🔹 Route: Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("ไม่พบข้อมูลผู้ใช้", "danger")
        return redirect(url_for('login'))

    files = File.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', username=user.username, role=user.role, files=files)

# หน้าลิ้งปุ่ม Navbar status

@app.route('/status')
def status():
    return render_template('status.html')



# หน้าลิ้งปุ่ม Navbar Home
@app.route('/user_dashboard')
def home():
    return render_template('user_dashboard.html')




if __name__ == "__main__":
    app.run(debug=True)

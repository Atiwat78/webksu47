from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
from flask import jsonify
from flask import Flask, render_template, session, redirect, url_for
from models import db, ContactMessage, User, File  # ✅ แก้เป็น ContactMessage
import os
print("Templates Path:", os.path.abspath("templates"))
print("Files in templates:", os.listdir("templates"))



# 🔹 ตั้งค่าแอป Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)


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
@app.route('/home')  # ✅ รองรับทั้ง "/" และ "/home"
def home():
    return render_template('home.html')



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
@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = "user"  # ✅ บังคับให้เป็น user
        
        faculty = request.form.get('faculty', '')  # ✅ ใช้ .get() เพื่อป้องกัน KeyError

        if password != confirm_password:
            flash("❌ รหัสผ่านไม่ตรงกัน! กรุณาลองอีกครั้ง", "danger")
            return redirect(url_for('register_user'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว", "danger")
            return redirect(url_for('register_user'))

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ", "success")
        return redirect(url_for('login'))  # ✅ เปลี่ยนเส้นทางไป login

    return render_template('register_user.html')  # ✅ เปลี่ยนชื่อไฟล์ HTML



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

    # ✅ ดึงข้อมูลของผู้ใช้ทั้งหมดและไฟล์ที่อัปโหลด
    users = User.query.options(db.joinedload(User.files)).all()  

    return render_template('admin_dashboard.html', 
                           username=session['username'], 
                           users=users)  # ✅ ส่ง users ไปแสดงไฟล์ของแต่ละคน


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


#    Route สำหรับดูไฟล์ของผู้ใช้แต่ละคน
@app.route('/admin/user/<int:user_id>')
def admin_user_files(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    files = File.query.filter_by(user_id=user.id).all()

    return render_template('admin_user_files.html', user=user, files=files)


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

    # ✅ ดึงข้อความจาก ContactMessage (แก้ไขจาก Message)
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()
    
    return render_template('admin_messages.html', messages=messages)


#ลบข้อความที่ userส่งมา
@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))  # ตรวจสอบว่าเป็น Admin หรือไม่

    message = ContactMessage.query.get(message_id)
    if message:
        db.session.delete(message)
        db.session.commit()
        flash("✅ ลบข้อความสำเร็จ!", "success")

    return redirect(url_for('admin_messages'))


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


#หน้าอัพเดทรหัสผ่าน 
# 🔹 Route: เปลี่ยนรหัสผ่าน (ไม่ใช้ Hash)
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # ✅ ตรวจสอบว่ารหัสผ่านเก่าถูกต้อง
        if user.password != old_password:
            flash("❌ รหัสผ่านเดิมไม่ถูกต้อง!", "danger")
            return redirect(url_for('change_password'))

        # ✅ ตรวจสอบว่ารหัสผ่านใหม่ตรงกัน
        if new_password != confirm_password:
            flash("❌ รหัสผ่านใหม่และยืนยันรหัสผ่านไม่ตรงกัน!", "danger")
            return redirect(url_for('change_password'))

        # ✅ อัปเดตรหัสผ่านใหม่ (ไม่มีการเข้ารหัส)
        user.password = new_password
        db.session.commit()

        flash("✅ เปลี่ยนรหัสผ่านสำเร็จ!", "success")
        return redirect(url_for('user_dashboard'))

    return render_template('change_password.html')



#เเสดงข้อมูลคณะ
@app.route('/faculties')
def faculties():
    faculty_list = [
        {"name": "คณะวิศวกรรมศาสตร์", "description": "มุ่งเน้นการเรียนการสอนด้านวิศวกรรมทุกสาขา"},
        {"name": "คณะวิทยาศาสตร์", "description": "เน้นการศึกษาวิจัยด้านวิทยาศาสตร์และเทคโนโลยี"},
        {"name": "คณะมนุษยศาสตร์", "description": "ศึกษาด้านศิลปศาสตร์และสังคมศาสตร์"},
        {"name": "คณะบริหารธุรกิจ", "description": "มุ่งเน้นการจัดการธุรกิจ การเงิน และการตลาด"},
    ]
    
    return render_template('faculty.html', faculties=faculty_list)

#สมัครสมาชิกคณะ
@app.route('/register_faculty', methods=['GET', 'POST'])
def register_faculty():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        faculty = request.form.get('faculty')  # ✅ ใช้ .get() เพื่อป้องกัน KeyError

        # ตรวจสอบว่ามีคณะถูกเลือกหรือไม่
        if not faculty:
            flash("❌ กรุณาเลือกคณะ!", "danger")
            return redirect(url_for('register_faculty'))

        # ตรวจสอบว่ารหัสผ่านตรงกัน
        if password != confirm_password:
            flash("❌ รหัสผ่านไม่ตรงกัน!", "danger")
            return redirect(url_for('register_faculty'))

        # ตรวจสอบว่าผู้ใช้ซ้ำหรือไม่
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว!", "danger")
            return redirect(url_for('register_faculty'))

        # บันทึกลงฐานข้อมูล
        new_user = User(username=username, password=password, role="faculty")
        db.session.add(new_user)
        db.session.commit()

        flash("✅ สมัครสมาชิกคณะสำเร็จ! กรุณาเข้าสู่ระบบ", "success")
        return redirect(url_for('login_faculty'))

    return render_template('register_faculty.html')



#เข้าสุ่ระบบคณะ
@app.route('/login_faculty', methods=['GET', 'POST'])
def login_faculty():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # ตรวจสอบข้อมูลผู้ใช้คณะ (ในฐานข้อมูล)
        faculty_user = User.query.filter_by(username=username, role='faculty').first()
        if faculty_user and faculty_user.password == password:
            session['user_id'] = faculty_user.id
            session['username'] = faculty_user.username
            session['role'] = faculty_user.role
            return redirect(url_for('faculty_dashboard'))  # ไปยังหน้า dashboard คณะ
        
        flash("❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!", "danger")
    
    return render_template('faculty_login.html')

#หน้าหลักคณะ
# 🔹 Route: Faculty Dashboard
@app.route('/faculty_dashboard')
def faculty_dashboard():
    if 'user_id' not in session or session.get('role') != 'faculty':
        return redirect(url_for('login_faculty'))  # ถ้าไม่ได้เข้าสู่ระบบให้กลับไปหน้า login

    return render_template('faculty_dashboard.html', username=session['username'])

# ดึงข้อมุลจากไฟล์ยูสเซอร์เเละอ่านไฟล์
def read_user_requests():
    data = []
    try:
        with open("user_requests.csv", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                data.append(row)
    except FileNotFoundError:
        data = []
    return data

# ✅ Route สำหรับหน้า "จัดการและอนุมัติคำขอ"
@app.route('/manage_requests')
def manage_requests():
    requests_data = read_user_requests()  # ✅ เรียกใช้ฟังก์ชันที่ถูกต้อง
    return render_template('manage_requests.html', requests=requests_data)

if __name__ == "__main__":
    app.run(debug=True)













if __name__ == "__main__":
    app.run(debug=True)

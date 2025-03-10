from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import csv

# ✅ ตั้งค่าแอป Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# ✅ ตั้งค่า SQLite Database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ ตั้งค่าอัปโหลดไฟล์
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}

# ✅ เรียกใช้ SQLAlchemy
db = SQLAlchemy(app)

# ✅ โมเดลฐานข้อมูล
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    faculty = db.Column(db.String(100), nullable=True)  # ✅ เพิ่มฟิลด์คณะ
    files = db.relationship('File', backref='user', lazy=True)

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default="รออนุมัติ")  # ✅ เพิ่มสถานะไฟล์

# ✅ สร้างฐานข้อมูลถ้ายังไม่มี
with app.app_context():
    db.create_all()

# ✅ ฟังก์ชันตรวจสอบไฟล์
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ Route: หน้าแรก
@app.route('/')
def home():
    return render_template('home.html')

# ✅ Route: Login
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
            return redirect(url_for('user_dashboard')) if user.role == 'user' else redirect(url_for('admin_dashboard'))

        flash("❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!", "danger")
    return render_template('login.html')

# ✅ Route: Register
@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        faculty = request.form.get('faculty', '')

        if password != confirm_password:
            flash("❌ รหัสผ่านไม่ตรงกัน!", "danger")
            return redirect(url_for('register_user'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว", "danger")
            return redirect(url_for('register_user'))

        new_user = User(username=username, password=password, role="user", faculty=faculty)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ สมัครสมาชิกสำเร็จ!", "success")
        return redirect(url_for('login'))

    return render_template('register_user.html')

# ✅ Route: Upload File
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

# ✅ Route: Profile
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', username=user.username, role=user.role, files=files)

# ✅ Route: Manage Requests
from flask import make_response, redirect, url_for, session, flash, render_template

@app.route('/manage_requests')
def manage_requests():
    # ตรวจสอบว่า user เข้าสู่ระบบหรือยัง
    if 'user_id' not in session or session.get('role') not in ['admin', 'faculty']:
        flash("⚠️ กรุณาเข้าสู่ระบบก่อน!", "warning")
        return redirect(url_for('login'))  # ถ้าไม่ได้ login ให้กลับไปหน้า login

    files = File.query.all()
    
    # ป้องกัน Browser Cache เพื่อไม่ให้ย้อนกลับได้
    response = make_response(render_template('manage_requests.html', files=files))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response


# ✅ Route: View File
@app.route('/uploads/<filename>')
def view_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ✅ Route: Delete File
@app.route('/delete_file/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = File.query.get(file_id)
    if file and (session.get('role') == 'admin' or file.user_id == session['user_id']):
        os.remove(file.file_path)  
        db.session.delete(file)    
        db.session.commit()
        flash("✅ ลบไฟล์สำเร็จ!", "success")

    return redirect(url_for('profile'))

#เข้าสุ่ระบบคณะ
@app.route('/faculty_login', methods=['GET', 'POST'])
def faculty_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ตรวจสอบว่าผู้ใช้มี role เป็น 'faculty'
        faculty_user = User.query.filter_by(username=username, role='faculty').first()
        if faculty_user and faculty_user.password == password:
            session['user_id'] = faculty_user.id
            session['username'] = faculty_user.username
            session['role'] = faculty_user.role
            return redirect(url_for('faculty_dashboard'))  # ไปยังหน้า dashboard คณะ

        flash("❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!", "danger")

    return render_template('faculty_login.html')



 # สมัครสมาชิกคณะ
@app.route('/register_faculty', methods=['GET', 'POST'])
def register_faculty():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        faculty = request.form.get('faculty')

        # ✅ ตรวจสอบว่ามีคณะถูกเลือกหรือไม่
        if not faculty:
            flash("❌ กรุณาเลือกคณะ!", "danger")
            return redirect(url_for('register_faculty'))

        # ✅ ตรวจสอบว่ารหัสผ่านตรงกัน
        if password != confirm_password:
            flash("❌ รหัสผ่านไม่ตรงกัน!", "danger")
            return redirect(url_for('register_faculty'))

        # ✅ ตรวจสอบว่าผู้ใช้ซ้ำหรือไม่
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว!", "danger")
            return redirect(url_for('register_faculty'))

        # ✅ บันทึกลงฐานข้อมูล
        new_user = User(username=username, password=password, role="faculty", faculty=faculty)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ สมัครสมาชิกคณะสำเร็จ! กรุณาเข้าสู่ระบบ", "success")
        return redirect(url_for('faculty_login'))

    return render_template('register_faculty.html')

#หน้าหลักคณะ
@app.route('/faculty_dashboard')
def faculty_dashboard():
    if 'user_id' not in session or session.get('role') != 'faculty':
        return redirect(url_for('faculty_login'))
    
    faculty_user = User.query.get(session['user_id'])
    response = make_response(render_template(
        'faculty_dashboard.html',
        username=session['username'],
        faculty=faculty_user.faculty  # ส่งข้อมูลคณะไปยังเทมเพลต
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response



# ✅ Route: Faculties Page (หน้าแสดงข้อมูลคณะ)
@app.route('/faculties')
def faculties():
    # ดึงข้อมูลจากฐานข้อมูล
    db_faculties = db.session.query(User.faculty).distinct().all()
    faculty_list_db = [f[0] for f in db_faculties if f[0]]

    # รายชื่อคณะที่กำหนดเอง (ถ้ามี)
    faculty_list_static = [
        {"name": "คณะวิศวกรรมศาสตร์", "description": "มุ่งเน้นการเรียนการสอนด้านวิศวกรรมทุกสาขา"},
        {"name": "คณะวิทยาศาสตร์", "description": "เน้นการศึกษาวิจัยด้านวิทยาศาสตร์และเทคโนโลยี"},
        {"name": "คณะมนุษยศาสตร์", "description": "ศึกษาด้านศิลปศาสตร์และสังคมศาสตร์"},
        {"name": "คณะบริหารธุรกิจ", "description": "มุ่งเน้นการจัดการธุรกิจ การเงิน และการตลาด"},
    ]

    # รวมข้อมูลจากฐานข้อมูลและ Static
    faculty_list = [{"name": f, "description": ""} for f in faculty_list_db] + faculty_list_static

    return render_template('faculties.html', faculties=faculty_list)


#เเสดงข้อมูลเจาะจง
@app.route('/faculty/<faculty_name>')
def faculty_detail(faculty_name):
    faculty_users = User.query.filter_by(faculty=faculty_name).all()  # ดึงข้อมูลสมาชิกของคณะนี้
    return render_template('faculty_detail.html', faculty_name=faculty_name, faculty_users=faculty_users)

#เปลี่ยนรหัสสำหรับคณะ
@app.route('/change_password_faculty', methods=['GET', 'POST'])
def change_password_faculty():
    if 'user_id' not in session or session.get('role') != 'faculty':
        return redirect(url_for('faculty_login'))

    faculty_user = User.query.get(session['user_id'])

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if faculty_user.password != old_password:
            flash("❌ รหัสผ่านเดิมไม่ถูกต้อง!", "danger")
            return redirect(url_for('change_password_faculty'))

        if new_password != confirm_password:
            flash("❌ รหัสผ่านใหม่และยืนยันรหัสผ่านไม่ตรงกัน!", "danger")
            return redirect(url_for('change_password_faculty'))

        faculty_user.password = new_password
        db.session.commit()

        flash("✅ เปลี่ยนรหัสผ่านสำเร็จ!", "success")
        return redirect(url_for('faculty_dashboard'))

    return render_template('change_password_faculty.html')



#อัพโหลดไฟล์
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


#ทำสถานะว่าอ่านเเล้วหรือยังไม่อ่าน
@app.route('/mark_as_read/<int:message_id>')
def mark_as_read(message_id):
    if 'user_id' not in session or session.get('role') != 'admin':  # ให้ Admin อ่านเท่านั้น
        flash("❌ คุณไม่มีสิทธิ์เข้าถึง", "danger")
        return redirect(url_for('login'))

    message = ContactMessage.query.get(message_id)
    if message:
        message.is_read = True
        db.session.commit()
        flash("✅ ทำเครื่องหมายว่าอ่านแล้ว!", "success")

    return redirect(url_for('manage_contacts'))






#เข้าสู่ระบบสมาชิก
from flask import make_response
@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))  # ถ้าไม่มี Session ให้กลับไป Login

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).all()

    # สร้าง Response และปิดการ Cache เพื่อไม่ให้กด Back แล้วย้อนกลับมาได้
    response = make_response(render_template('user_dashboard.html', username=user.username, files=files))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

#สถานะ
@app.route('/status')
def status():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).all()
    
    return render_template('status.html', username=user.username, files=files)




#เปลี่ยนรหัส user
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

        # ✅ อัปเดตรหัสผ่านใหม่
        user.password = new_password
        db.session.commit()

        flash("✅ เปลี่ยนรหัสผ่านสำเร็จ!", "success")
        return redirect(url_for('user_dashboard'))

    return render_template('change_password.html')

#ติดต่อเรา
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


@app.route('/approve_file/<int:file_id>')
def approve_file(file_id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'faculty']:  
        flash("❌ คุณไม่มีสิทธิ์อนุมัติ", "danger")
        return redirect(url_for('login'))

    file = File.query.get(file_id)
    if file and file.status != "อนุมัติแล้ว":  # เช็คว่าไฟล์ยังไม่ได้อนุมัติ
        file.status = "อนุมัติแล้ว"
        db.session.commit()
        flash("✅ อนุมัติเอกสารเรียบร้อย!", "success")

    return redirect(url_for('manage_requests'))



#หน้าดูระบบ
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))  # ถ้าไม่มี session หรือไม่ใช่ admin ให้กลับไป login

    return render_template('admin_dashboard.html', username=session['username'])



@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')







# ✅ Route: Logout
@app.route('/logout')
def logout():
    role = session.get('role')  
    session.clear()  

    if role == 'faculty':
        return redirect(url_for('faculty_login'))  
    else:
        return redirect(url_for('login'))



# ✅ Run Flask App
if __name__ == "__main__":
    app.run(debug=True)

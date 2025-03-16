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
    email = db.Column(db.String(150), unique=True, nullable=False)  # ✅ เพิ่ม email
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
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

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']  # ✅ รับค่า email
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("❌ รหัสผ่านไม่ตรงกัน!", "danger")
            return redirect(url_for('register_user'))

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()  # ✅ เช็คอีเมลซ้ำ

        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว", "danger")
            return redirect(url_for('register_user'))
        
        if existing_email:
            flash("❌ อีเมลนี้ถูกใช้ไปแล้ว", "danger")
            return redirect(url_for('register_user'))

        new_user = User(username=username, email=email, password=password, role="user")  # ✅ บันทึก email
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
    return render_template('profile.html', username=user.username, email=user.email, role=user.role, files=files)

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

#สถานะรอตรวจสอบไฟล์
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


@app.route('/approve_file/<int:file_id>', methods=['POST'])
def approve_file(file_id):
    # ✅ ตรวจสอบว่าเป็นแอดมิน
    if not session.get('admin'):  # ✅ ใช้ session['admin'] แทน role
        return jsonify({"status": "error", "message": "❌ คุณไม่มีสิทธิ์อนุมัติไฟล์นี้"}), 403

    file = File.query.get(file_id)
    if not file:
        return jsonify({"status": "error", "message": "❌ ไม่พบไฟล์"}), 404

    # ✅ อัปเดตสถานะเป็น "อนุมัติแล้ว"
    file.status = "อนุมัติแล้ว"
    db.session.commit()

    return jsonify({"status": "success", "message": f"✅ ไฟล์ {file.filename} ได้รับการอนุมัติแล้ว", "file_id": file_id, "new_status": file.status})


#เช็คสถานะเเอดมิน
@app.route('/check_session')
def check_session():
    return jsonify({"user_id": session.get('user_id'), "role": session.get('role')})





#หน้าดูระบบ
@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin'):  # ✅ ตรวจสอบว่า session['admin'] เป็น True หรือไม่
        flash("⚠️ กรุณาเข้าสู่ระบบแอดมิน!", "warning")
        return redirect(url_for('admin_login'))

    users = User.query.all()  # ดึงข้อมูลผู้ใช้ทั้งหมด
    files = File.query.all()  # ดึงไฟล์ทั้งหมดจากฐานข้อมูล
    total_users = len(users)  # นับจำนวนผู้ใช้ทั้งหมด

    return render_template('admin_dashboard.html', 
                           username=ADMIN_USERNAME,  # ✅ ใช้ username ของแอดมิน
                           users=users, 
                           files=files, 
                           total_users=total_users)




@app.route('/help')
def help():
    return render_template('help.html')

#เข้าสู่ระบบเเอดมิน
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ เช็คว่าเป็นบัญชีแอดมินหรือไม่
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True  # ตั้งค่า session ให้รู้ว่าเป็นแอดมิน
            return redirect(url_for('admin_dashboard'))

        flash("❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!", "danger")

    return render_template('admin_login.html')


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin01"  # รหัสเเอดมิน

@app.route('/admin_messages')
def admin_messages():
    return render_template('admin_messages.html')

@app.route('/delete_user/<int:user_id>', methods=['POST', 'GET'])
def delete_user(user_id):
    user = User.query.get(user_id)
    
    if user:
        # ✅ ลบไฟล์ทั้งหมดของผู้ใช้ก่อน
        files = File.query.filter_by(user_id=user.id).all()
        for file in files:
            if os.path.exists(file.file_path):  # เช็คว่าไฟล์มีอยู่จริงไหม
                os.remove(file.file_path)  # ลบไฟล์จากระบบไฟล์
            db.session.delete(file)  # ลบไฟล์จากฐานข้อมูล
        
        db.session.delete(user)  # ลบผู้ใช้
        db.session.commit()  # บันทึกการเปลี่ยนแปลง

        flash('ลบผู้ใช้สำเร็จ', 'success')
    else:
        flash('ไม่พบผู้ใช้', 'danger')

    return redirect(url_for('manage_users'))

#จัดการผู้ใช้

@app.route('/manage_users')
def manage_users():
    users = User.query.all()  # ดึงข้อมูลผู้ใช้ทั้งหมดจากฐานข้อมูล
    return render_template('manage_users.html', users=users)



@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("ไม่พบผู้ใช้ที่ต้องการแก้ไข", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        flash("อัปเดตข้อมูลสำเร็จ", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)
#ดูยูส
@app.route('/view_user/<int:user_id>')
def view_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("ไม่พบข้อมูลผู้ใช้", "danger")
        return redirect(url_for('manage_users'))  # ถ้าหาไม่เจอให้กลับไปหน้า manage_users

    # ✅ ดึงข้อมูลไฟล์ที่ user อัปโหลด
    files = File.query.filter_by(user_id=user.id).all()

    return render_template('view_user.html', user=user, files=files)



#เพิ่มผู้ใช้
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว!", "danger")
            return redirect(url_for('add_user'))

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ เพิ่มผู้ใช้สำเร็จ!", "success")
        return redirect(url_for('manage_users'))

    return render_template('add_user.html')




#หน้าตั้งค่า
@app.route('/settings')
def settings():
    if 'admin' not in session:  # ✅ ตรวจสอบว่าเป็นแอดมินหรือไม่
        flash("❌ กรุณาเข้าสู่ระบบแอดมิน!", "danger")
        return redirect(url_for('admin_login'))  # ถ้าไม่ใช่แอดมิน ให้กลับไปหน้า login

    admin = User.query.filter_by(username=ADMIN_USERNAME).first()  # ดึงข้อมูลแอดมินจากฐานข้อมูล
    if not admin:
        flash("❌ ไม่พบข้อมูลแอดมิน!", "danger")
        return redirect(url_for('admin_dashboard'))

    return render_template('settings.html', user=admin)  # ส่ง user ไปยัง template




@app.route('/reports')
def reports():
    if 'admin' not in session:  # ✅ เช็คว่าผู้ใช้ล็อกอินเป็นแอดมินหรือไม่
        flash("❌ คุณไม่มีสิทธิ์เข้าถึงหน้านี้!", "danger")
        return redirect(url_for('admin_login'))  # ถ้าไม่ใช่แอดมิน ให้ไปที่หน้า login

    # ✅ ดึงข้อมูลสถิติ
    total_users = User.query.count()  # จำนวนผู้ใช้ทั้งหมด
    total_files = File.query.count()  # จำนวนไฟล์ที่อัปโหลดทั้งหมด
    approved_files = File.query.filter_by(status="อนุมัติแล้ว").count()  # จำนวนไฟล์ที่อนุมัติ
    pending_files = File.query.filter_by(status="รออนุมัติ").count()  # จำนวนไฟล์ที่รออนุมัติ

    # ✅ ดึงตำแหน่งทางวิชาการของผู้ใช้
    faculty_stats = db.session.query(User.faculty, db.func.count(User.faculty)).group_by(User.faculty).all()

    # ✅ ส่งข้อมูลไปยัง reports.html
    return render_template('reports.html', 
                           total_users=total_users, 
                           total_files=total_files, 
                           approved_files=approved_files, 
                           pending_files=pending_files, 
                           faculty_stats=faculty_stats)













@app.route('/logout')
def logout():
    user_role = session.get('role')  # ดึงบทบาทผู้ใช้จาก session
    session.clear()  # เคลียร์ session ทั้งหมด

    flash("ออกจากระบบเรียบร้อย!", "success")

    # ถ้าเป็นแอดมินให้ไปที่หน้า login ของแอดมิน
    if user_role == 'admin_dashboard':
        return redirect(url_for('admin_login'))
    
    # ถ้าเป็น user ปกติให้ไปที่หน้า login ของ user
    return redirect(url_for('login'))



# ✅ Run Flask App
if __name__ == "__main__":
    app.run(debug=True)

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

# Initialize the SQLAlchemy object
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False)
    faculty = db.Column(db.String(100), nullable=True)
    
    # ความสัมพันธ์กับเอกสารและไฟล์
    document_requests = db.relationship('DocumentRequest', back_populates='user', lazy=True)
    files = db.relationship('File', back_populates='user', lazy=True)  # ✅ เพิ่มตรงนี้


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="รอตรวจสอบ")
    comment = db.Column(db.Text, nullable=True)

    # คีย์ต่างประเทศ (Foreign Key)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # ฟิลด์เวลาต่าง ๆ
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    review_date = db.Column(db.DateTime, nullable=True)
    approve_date = db.Column(db.DateTime, nullable=True)
    
    # สร้างความสัมพันธ์กับตาราง User
    # ถ้าจะใช้ back_populates ใน User model ให้ประกาศ user.relationship('File', back_populates='user')
    # หรือถ้าจะใช้ backref ก็พอ แต่ไม่ต้องซ้ำกันทั้งสองฝั่ง
    user = db.relationship('User', back_populates='files')



class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))  # <-- เพิ่ม field นี้ถ้ายังไม่มี
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_read = db.Column(db.Boolean, default=False)
    
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())


class DocumentRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    
    # Define the relationship back to User
    user = db.relationship('User', back_populates='document_requests')

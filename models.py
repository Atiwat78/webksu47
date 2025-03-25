from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize the SQLAlchemy object
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False)  # เช่น admin, user
    
    # Define the relationship with DocumentRequest
    document_requests = db.relationship('DocumentRequest', back_populates='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="รอตรวจสอบ")
    comment = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # เพิ่มคอลัมน์ upload_date เพื่อเก็บวันที่อัปโหลดไฟล์
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', back_populates='files')





class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

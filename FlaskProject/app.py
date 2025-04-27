from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # 验证必要字段
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data or not data[field].strip():
            return jsonify({'message': f'{field} is required'}), 400

    username = data['username'].strip()
    email = data['email'].strip().lower()
    password = data['password']

    # 用户名验证（4-20位字母数字）
    if not re.match(r'^[a-zA-Z0-9]{4,20}$', username):
        return jsonify({'message': 'Username must be 4-20 alphanumeric characters'}), 400

    # 邮箱格式验证
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return jsonify({'message': 'Invalid email format'}), 400

    # 密码强度验证（至少8位，包含大小写和数字）
    if len(password) < 8 or not re.search(r'[A-Z]', password) \
            or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
        return jsonify({'message': 'Password must be at least 8 characters with uppercase, lowercase and numbers'}), 400

    # 检查用户名和邮箱是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 409

    # 创建新用户
    try:
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
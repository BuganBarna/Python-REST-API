from flask import Flask,jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, JWTManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.config['JWT_SECRET_KEY'] = '123'  
jwt = JWTManager(app)


class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def return_user(self):
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email
        }

@app.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()

    if not request_data.get('email') or not request_data.get('password'):
        jsonify(message="Email and password are required!"), 400

    email = request_data.get('email')
    password = request_data.get('password')

    user_data = UserModel.query.filter_by(email=email).first()
    if user and check_password_hash(user_data.password, password):
        token = create_access_token(identity=str(user_data.id))
        return jsonify(jwt_token=token), 200
    return jsonify(message="Invalid credentials"), 401

@app.route('/register', methods=['POST'])
def register():
    request_data = request.get_json()
    if UserModel.query.filter_by(email=request_data['email']).first():
        return jsonify({"message": "Email already exists"}), 409
        
    new_user = UserModel(name=request_data['name'], email=request_data['email'], password=generate_password_hash(request_data['password']))
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="You have successfully registered"), 200



@app.route('/api/users', methods=['GET'])
@jwt_required()
def users():
    return jsonify([user.return_user() for user in UserModel.query.all()])


@app.route('/api/user/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
def user(id):
    user_data = UserModel.query.get(id)
    if not user_data:
        return jsonify({"message": "User not found"}), 404

    if request.method == 'GET':
        return jsonify(user_data.return_user())
    
    if request.method == 'PATCH':
        request_data = request.get_json()
        user_data.name = request_data['name']
        user_data.email = request_data['email']
        db.session.commit()
        return jsonify(user_data.return_user())

    if request.method == 'DELETE':
        db.session.delete(user_data)
        db.session.commit()
        return jsonify({"message": "User deleted"})


@app.route('/')
def home():
    return '<h1>MAIN PAGE</h1>'

if __name__ == '__main__':
    app.run(debug=True)



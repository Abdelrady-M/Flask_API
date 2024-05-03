#import important packages 
import json
from flask import Flask, request, session, jsonify
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, unset_jwt_cookies, jwt_required, JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS

from models import db, User, Item

#config file for flask and database connections
app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = 'flask_task'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskdb.db'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = True

#jwt authentication, bcrypt
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

database_value = 50

#create database tables if they don't exist, initialization app
db.init_app(app)
with app.app_context():
    db.create_all()


#config routes
@app.route ('/')
def index():
    return "<p>Hello, World!</p>"

@app.route('/login', methods=["POST"])
def create_token():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
  
    user = User.query.filter_by(email=email).first()
    #if email != "test" or password != "test":
    #    return {"msg": "Wrong email or password"}, 401
    if user is None:
        return jsonify({"error": "Wrong email or passwords"}), 401
      
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401
    
    
    # Fetch the user's name from the database
    user_name = user.name if user else None
      
    access_token = create_access_token(identity=email)
    response = {"access_token":access_token}
  
    return jsonify({
        "name": user_name,
        "email": email,
        "access_token": access_token
    })
    #return response
    
@app.route("/signup", methods=["POST"])
def signup():
    email = request.json["email"]
    password = request.json["password"]
    name = request.json["name"]

    user_exists = User.query.filter_by(email=email).first() is not None

    if user_exists:
        return jsonify({"error": "Email already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "id": new_user.id,
        "email": new_user.email,
        "name": new_user.name,
    })

@app.route('/items', methods=["GET"])
def get_items():
    items = Item.query.all()
    items_list = [{"id": item.id, "name": item.name, "quantity": item.quantity} for item in items]
    return jsonify(items_list)

@app.route('/items', methods=["POST"])
@jwt_required()
def create_item():
    data = request.get_json()
    name = data.get("name")
    quantity = data.get("quantity")
    if not name or not quantity:
        return jsonify({"error": "Name and quantity are required"}), 400
    new_item = Item(name=name, quantity=quantity)
    db.session.add(new_item)
    db.session.commit()
    return jsonify({"id": new_item.id, "name": new_item.name, "quantity": new_item.quantity}), 201

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token 
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response
    
    

@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response



#run the application on port 5000
if __name__ == '__main__':
    app.run(debug=True, port = 9000)
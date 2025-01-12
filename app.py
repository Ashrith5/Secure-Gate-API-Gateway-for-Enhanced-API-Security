from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Secret key for JWT
app.config['JWT_SECRET_KEY'] = 'supersecretkey123'  # Change this to a strong key
jwt = JWTManager(app)

# Fake user database
users = {
    "user1": "password1",
    "user2": "password2"
}

# Set up rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

# Login route to authenticate and get token
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Apply rate limiting to this route
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    if username in users and users[username] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    return jsonify({"msg": "Bad username or password"}), 401

# Protected route - requires valid JWT token
@app.route('/protected', methods=['GET'])
@jwt_required()
@limiter.limit("5 per minute")  # Apply rate limiting to this route
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)

# IoT-Device-Access-Control-System
This project develops an access control system for IoT devices, allowing only authorized users and devices to interact with the IoT network. It employs Role-Based Access Control (RBAC) and uses token-based authentication
from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

# Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# In-memory user database with roles
USERS = {
    "device1": {"password": "password1", "role": "Admin"},
    "device2": {"password": "password2", "role": "User"},
    "device3": {"password": "password3", "role": "Viewer"}
}

# Role-based access control permissions
PERMISSIONS = {
    "Admin": ["read", "write", "delete"],
    "User": ["read", "write"],
    "Viewer": ["read"]
}

# Token generation
def generate_token(device_id, role):
    token = jwt.encode(
        {"device_id": device_id, "role": role, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )
    return token

# Decorator for token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.device_id = data['device_id']
            request.role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 403
        return f(*args, **kwargs)
    return decorated

# Authentication route
@app.route('/auth', methods=['POST'])
def auth():
    auth_data = request.json
    device_id = auth_data.get("device_id")
    password = auth_data.get("password")

    if device_id in USERS and USERS[device_id]['password'] == password:
        role = USERS[device_id]['role']
        token = generate_token(device_id, role)
        return jsonify({"token": token})
    else:
        return jsonify({"message": "Invalid credentials!"}), 401

# Route with role-based access control
@app.route('/resource/<action>', methods=['GET'])
@token_required
def resource(action):
    role = request.role
    if action in PERMISSIONS.get(role, []):
        return jsonify({"message": f"Action '{action}' performed successfully by {role}!"})
    else:
        return jsonify({"message": f"Access denied for action '{action}' with role '{role}'!"}), 403

# Real-time monitoring endpoint
@app.route('/monitor', methods=['GET'])
@token_required
def monitor():
    return jsonify({"message": f"Device {request.device_id} is authenticated with role {request.role}."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

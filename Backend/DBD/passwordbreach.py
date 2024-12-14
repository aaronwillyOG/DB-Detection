from flask import Flask, request, jsonify
import requests
import hashlib

app = Flask(__name__)

# Function to check if the password is in the Pwned Passwords database
def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in response.text

@app.route('/check_password', methods=['POST'])
def check_password():
    # Get password from the request body
    data = request.get_json()
    password_to_check = data.get("password", "")
    
    if not password_to_check:
        return jsonify({"error": "No password provided"}), 400

    # Check if the password has been compromised
    if check_password_breach(password_to_check):
        return jsonify({"message": "This password has been compromised!"}), 200
    else:
        return jsonify({"message": "This password is safe."}), 200

if __name__ == '__main__':
    app.run()
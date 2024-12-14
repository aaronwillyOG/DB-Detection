import requests
import hashlib

def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in response.text

password_to_check = "Aaron-123"
if check_password_breach(password_to_check):
    print("This password has been compromised!")
else:
    print("This password is safe.")
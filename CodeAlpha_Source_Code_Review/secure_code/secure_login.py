import hashlib

# Function to hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Stored credentials (hashed)
stored_username = "admin"
stored_password = hash_password("admin123")

username = input("Enter username: ")
password = input("Enter password: ")

# Input validation
if not username or not password:
    print("Username and password cannot be empty")
else:
    if username == stored_username and hash_password(password) == stored_password:
        print("Login Successful")
    else:
        print("Invalid Credentials")

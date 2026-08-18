from app.auth.password_hashing import hash_password, verify_password

password = "Admin123"

hashed = hash_password(password)

print("Hashed Password:", hashed)

print("Verification:", verify_password(password, hashed))
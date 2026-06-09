from werkzeug.security import generate_password_hash, check_password_hash

hash = generate_password_hash('principal123', method='pbkdf2:sha256')
print("HASH:", hash)
print("CHECK:", check_password_hash(hash, 'principal123'))
from cryptography.fernet import Fernet
SECRET_KEY = Fernet.generate_key()
print(SECRET_KEY)

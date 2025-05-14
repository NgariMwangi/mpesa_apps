from cryptography.fernet import Fernet
def encrypt():
    # Shared secret key (must match the API's SECRET_KEY)
    SECRET_KEY = b"oVRdE2Y0KaygAhDWVyp2IbT_U_Qte26tWqVoMAIeAfY="
    cipher_suite = Fernet(SECRET_KEY)

    # Consumer key and secret received from the API
    consumer_key = "fca594928963ee1f178fd5d767d21bf8"
    consumer_secret = "cf15e5f65736f5269c2b2e8dd1e687c06d53d54415e2e5268df59d97ddb2c71f"

    # Encrypt the consumer key and secret into a token
    data = f"{consumer_key}:{consumer_secret}".encode()
    encrypted_token = cipher_suite.encrypt(data).decode()

    print("Encrypted Token:", encrypted_token)
    return encrypted_token

print(encrypt())

from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import secrets
import requests
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from cryptography.fernet import Fernet  # For encryption and decryption

# Generate a secret key for encryption (shared between client and API)
SECRET_KEY = "oVRdE2Y0KaygAhDWVyp2IbT_U_Qte26tWqVoMAIeAfY="
cipher_suite = Fernet(SECRET_KEY)

# SQLite database setup
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base for SQLAlchemy models
Base = declarative_base()

# SQLAlchemy models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)

class App(Base):
    __tablename__ = "apps"
    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String, index=True)
    consumer_key = Column(String, unique=True, index=True)
    consumer_secret = Column(String, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    webhook_url = Column(String, nullable=True)  # New field for webhook URL

# Create tables in the database
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to authenticate requests using encrypted token
def authenticate_request(
    encrypted_token: str = Header(..., alias="Encrypted-Token"),
    db: Session = Depends(get_db)
):
    if not encrypted_token:
        raise HTTPException(status_code=401, detail="Encrypted-Token header is required")

    # Decrypt the token to get consumer key and secret
    consumer_key, consumer_secret = decrypt_token(encrypted_token)

    # Validate the consumer key and secret
    app = db.query(App).filter(App.consumer_key == consumer_key, App.consumer_secret == consumer_secret).first()
    if not app:
        raise HTTPException(status_code=401, detail="Invalid token")

    return app

# Pydantic models for request validation
class CreateUserRequest(BaseModel):
    username: str
    email: str

class CreateAppRequest(BaseModel):
    app_name: str

class UpdateWebhookRequest(BaseModel):
    webhook_url: str

class EncryptedTokenRequest(BaseModel):
    encrypted_token: str

# Utility function to decrypt token
def decrypt_token(encrypted_token: str) -> tuple[str, str]:
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_token.encode())
        consumer_key, consumer_secret = decrypted_data.decode().split(":")
        return consumer_key, consumer_secret
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid token")

# Route to create a new user
@app.post("/create_user")
def create_user(request: CreateUserRequest, db: Session = Depends(get_db)):
    # Check if username or email already exists
    if db.query(User).filter(User.username == request.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == request.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Create the user
    user = User(username=request.username, email=request.email)
    db.add(user)
    db.commit()
    db.refresh(user)

    # Trigger webhooks for all apps associated with the user
    apps = db.query(App).filter(App.user_id == user.id).all()
    for app in apps:
        trigger_webhook(app, {
            "event": "user_created",
            "user_id": user.id,
            "username": user.username,
            "email": user.email
        })

    return {"user_id": user.id, "username": user.username, "email": user.email}

# Route to create a new app for a user
@app.post("/create_app/{user_id}")
def create_app(user_id: int, request: CreateAppRequest, db: Session = Depends(get_db)):
    # Check if the user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate consumer key and secret
    consumer_key = secrets.token_hex(16)
    consumer_secret = secrets.token_hex(32)

    # Create the app
    app = App(
        app_name=request.app_name,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        user_id=user_id
    )
    db.add(app)
    db.commit()
    db.refresh(app)

    return {
        "app_id": app.id,
        "app_name": app.app_name,
        "consumer_key": consumer_key,  # Return raw consumer key and secret to the client
        "consumer_secret": consumer_secret
    }

# Route to register/update webhook URL for an app
@app.post("/register_webhook/{app_id}")
def register_webhook(app_id: int, request: UpdateWebhookRequest, db: Session = Depends(get_db), app: App = Depends(authenticate_request)
):
    # Ensure the app_id matches the authenticated app
    if app.id != app_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Update the webhook URL
    app.webhook_url = request.webhook_url
    db.commit()
    db.refresh(app)
    return {"message": "Webhook URL updated successfully", "webhook_url": app.webhook_url}

# Utility function to trigger webhook
def trigger_webhook(app: App, payload: dict):
    if not app.webhook_url:
        return  # No webhook URL registered

    try:
        response = requests.post(app.webhook_url, json=payload)
        response.raise_for_status()
    except requests.RequestException as e:
        # Handle any errors that occur during the webhook request
        print(f"Failed to trigger webhook: {e}")



# Protected route
@app.get("/protected")
def protected_route(app: App = Depends(authenticate_request)):
    return {
        'message': 'You have access to the protected route!',
        'app_name': app.app_name,
        'user_id': app.user_id
    }

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
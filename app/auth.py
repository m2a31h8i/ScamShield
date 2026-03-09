from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app import models

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str):
    password = password[:72]   # limit argon2 input
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    plain = plain[:72]
    return pwd_context.verify(plain, hashed)

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user
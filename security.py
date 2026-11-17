import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import bcrypt
import jwt

load_dotenv()


SECRET_KEY = os.getenv("JWT_SECRET", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def hash_password(password: str) -> str:
    # bcrypt מוגבל ל-72 בייטים — חותכים כדי למנוע ValueError
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8")[:72], password_hash.encode("utf-8"))


def create_access_token(user_id: int, username: str) -> str:
    """יוצרת JWT חתום עבור המשתמש."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """מפענחת ומאמתת טוקן. מרימה jwt.PyJWTError אם אינו תקין או שפג תוקפו."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
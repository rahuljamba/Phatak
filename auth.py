import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

# Logger
logger = logging.getLogger("phatak_auth")

# Configuration & Paths
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PHATAK_DB_PATH", BASE_DIR / "phatak.db"))
ENV_MODE = os.environ.get("ENV_MODE", "dev").lower()
AUTH_SECRET_KEY = os.environ.get(
    "AUTH_SECRET_KEY", "phatak-punjab-auth-secret-key-32chars-minimum-prod"
)
OTP_EXPIRY_SECONDS = 300  # 5 minutes
MAX_OTP_ATTEMPTS = 5
TOKEN_EXPIRY_SECONDS = 86400 * 30  # 30 days

# Router definition
router = APIRouter(prefix="/apis/auth", tags=["Authentication"])


# ============================================================================
# Database Management (SQLite)
# ============================================================================

@contextmanager
def get_db():
    """Provides a transactional SQLite database connection."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Initializes tables for users and OTP requests."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mobile TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile);")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS otp_requests (
                mobile TEXT PRIMARY KEY,
                otp_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL
            );
        """)
    logger.info(f"Initialized SQLite database at {DB_PATH}")


# Auto-initialize DB on import
init_db()


# ============================================================================
# Helpers: Normalization, OTP Hashing & JWT-Style HMAC Tokens
# ============================================================================

def normalize_indian_mobile(mobile_str: str) -> Optional[str]:
    """
    Normalizes and validates a 10-digit Indian mobile number to +91XXXXXXXXXX.
    Accepts formats like:
      - 9876543210
      - +919876543210
      - 09876543210
      - 919876543210
      - +91 98765 43210 / 98765-43210
    Valid Indian mobile numbers must start with 6, 7, 8, or 9.
    """
    if not mobile_str:
        return None
    cleaned = re.sub(r"[\s\-\(\)\.]", "", str(mobile_str).strip())
    if cleaned.startswith("+91"):
        digits = cleaned[3:]
    elif cleaned.startswith("0") and len(cleaned) == 11:
        digits = cleaned[1:]
    elif cleaned.startswith("91") and len(cleaned) == 12:
        digits = cleaned[2:]
    else:
        digits = cleaned

    if re.match(r"^[6-9]\d{9}$", digits):
        return f"+91{digits}"
    return None


def generate_otp() -> str:
    """Generates a secure, cryptographically random 6-digit OTP."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(mobile: str, otp: str, salt: str) -> str:
    """Computes an HMAC-SHA256 hash of the mobile, OTP, and salt."""
    key = AUTH_SECRET_KEY.encode("utf-8")
    payload = f"{mobile}:{otp}:{salt}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def create_access_token(user_id: int, mobile: str) -> str:
    """
    Generates a secure HMAC-SHA256 Bearer Token using only the Python standard library.
    Follows standard RFC 7519 JWT structure: header.payload.signature.
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "uid": user_id,
        "mob": mobile,
        "iat": now,
        "exp": now + TOKEN_EXPIRY_SECONDS,
    }

    h_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signing_input = f"{b64url_encode(h_bytes)}.{b64url_encode(p_bytes)}"
    sig = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validates and decodes the HMAC-SHA256 Bearer Token.
    Returns the payload dictionary if valid and not expired, else None.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h_b64, p_b64, s_b64 = parts
    signing_input = f"{h_b64}.{p_b64}"
    expected_sig = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()

    try:
        given_sig = b64url_decode(s_b64)
        if not hmac.compare_digest(expected_sig, given_sig):
            return None
        payload_bytes = b64url_decode(p_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception as e:
        logger.debug(f"Token decoding failed: {e}")
        return None


# ============================================================================
# Pydantic Request / Response Models
# ============================================================================

class SendOTPRequest(BaseModel):
    mobile: str = Field(
        ...,
        description="10-digit Indian mobile number (e.g. 9876543210 or +919876543210)",
        examples=["9876543210"],
    )


class VerifyOTPRequest(BaseModel):
    mobile: str = Field(..., description="10-digit Indian mobile number")
    otp: str = Field(..., description="6-digit verification code", min_length=4, max_length=8)


# ============================================================================
# Auth Dependency: get_current_user
# ============================================================================

async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    FastAPI dependency that extracts and validates the Bearer token from the
    Authorization header, verifying against the SQLite database.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("uid")
    mobile = payload.get("mob")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, mobile, created_at, last_login_at FROM users WHERE id = ?;", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account associated with this token does not exist.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {
            "id": row["id"],
            "mobile": row["mobile"],
            "created_at": row["created_at"],
            "last_login_at": row["last_login_at"],
        }


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/send-otp", summary="Send 6-Digit Mobile OTP", status_code=status.HTTP_200_OK)
async def send_otp(req: SendOTPRequest):
    """
    Normalizes 10-digit Indian mobile number, checks if user already exists,
    generates a secure 6-digit OTP, stores its HMAC hash with a 5-minute expiry,
    and returns delivery metadata (including dev_otp when ENV_MODE != 'prod').
    """
    norm_mobile = normalize_indian_mobile(req.mobile)
    if not norm_mobile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Indian mobile number. Please enter a valid 10-digit number starting with 6, 7, 8, or 9.",
        )

    now = time.time()
    expires_at = now + OTP_EXPIRY_SECONDS
    otp = generate_otp()
    salt = secrets.token_hex(8)
    token_hash = hash_otp(norm_mobile, otp, salt)

    with get_db() as conn:
        cursor = conn.cursor()
        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE mobile = ?;", (norm_mobile,))
        user_row = cursor.fetchone()
        is_new_user = user_row is None

        # Upsert into otp_requests table
        cursor.execute("""
            INSERT INTO otp_requests (mobile, otp_hash, salt, attempts, expires_at, created_at)
            VALUES (?, ?, ?, 0, ?, ?)
            ON CONFLICT(mobile) DO UPDATE SET
                otp_hash = excluded.otp_hash,
                salt = excluded.salt,
                attempts = 0,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at;
        """, (norm_mobile, token_hash, salt, expires_at, now))

    resp: Dict[str, Any] = {
        "status": "ok",
        "mobile": norm_mobile,
        "is_new_user": is_new_user,
        "expires_in_seconds": OTP_EXPIRY_SECONDS,
        "message": f"OTP successfully sent to {norm_mobile}.",
    }

    # Include dev_otp for rapid local / QA testing when not in strict production mode
    if ENV_MODE != "prod":
        resp["dev_otp"] = otp
        logger.info(f"[DEV MODE] Generated OTP for {norm_mobile}: {otp}")

    return resp


@router.post("/verify-otp", summary="Verify OTP & Login / Register User", status_code=status.HTTP_200_OK)
async def verify_otp(req: VerifyOTPRequest):
    """
    Verifies 6-digit OTP against HMAC hash, handles expiry and max 5 attempts.
    If new user, registers in `users`. If existing user, updates `last_login_at`.
    Returns an HMAC-SHA256 signed Bearer token and redirect URL (/dashboard).
    """
    norm_mobile = normalize_indian_mobile(req.mobile)
    if not norm_mobile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Indian mobile number.",
        )

    otp_clean = req.otp.strip()
    now_ts = time.time()
    iso_now = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT otp_hash, salt, attempts, expires_at FROM otp_requests WHERE mobile = ?;",
            (norm_mobile,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active OTP request found for this mobile number. Please request a new OTP.",
            )

        stored_hash = row["otp_hash"]
        salt = row["salt"]
        attempts = row["attempts"]
        expires_at = row["expires_at"]

        # Check max attempts
        if attempts >= MAX_OTP_ATTEMPTS:
            cursor.execute("DELETE FROM otp_requests WHERE mobile = ?;", (norm_mobile,))
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum verification attempts exceeded. Please request a fresh OTP.",
            )

        # Check expiry
        if now_ts > expires_at:
            cursor.execute("DELETE FROM otp_requests WHERE mobile = ?;", (norm_mobile,))
            conn.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has expired. Please request a new OTP.",
            )

        # Verify OTP HMAC hash
        computed_hash = hash_otp(norm_mobile, otp_clean, salt)
        if not hmac.compare_digest(stored_hash, computed_hash):
            new_attempts = attempts + 1
            cursor.execute(
                "UPDATE otp_requests SET attempts = ? WHERE mobile = ?;",
                (new_attempts, norm_mobile),
            )
            conn.commit()
            remaining = max(0, MAX_OTP_ATTEMPTS - new_attempts)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid OTP entered. {remaining} attempt(s) remaining.",
            )

        # Correct OTP verified: delete request from pending table
        cursor.execute("DELETE FROM otp_requests WHERE mobile = ?;", (norm_mobile,))

        # Check if user already exists
        cursor.execute("SELECT id, created_at FROM users WHERE mobile = ?;", (norm_mobile,))
        existing_user = cursor.fetchone()

        if existing_user:
            action = "logged_in"
            user_id = existing_user["id"]
            cursor.execute("UPDATE users SET last_login_at = ? WHERE id = ?;", (iso_now, user_id))
        else:
            action = "registered"
            cursor.execute(
                "INSERT INTO users (mobile, created_at, last_login_at) VALUES (?, ?, ?);",
                (norm_mobile, iso_now, iso_now),
            )
            user_id = cursor.lastrowid

    # Generate Bearer Token
    token = create_access_token(user_id=user_id, mobile=norm_mobile)

    return {
        "status": "authenticated",
        "action": action,
        "token": token,
        "user": {
            "id": user_id,
            "mobile": norm_mobile,
        },
        "redirect": "/dashboard",
    }


@router.get("/me", summary="Get Authenticated User Profile", status_code=status.HTTP_200_OK)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Validates Bearer token from the Authorization header and returns user identity.
    """
    return {
        "id": current_user["id"],
        "mobile": current_user["mobile"],
        "created_at": current_user.get("created_at"),
        "last_login_at": current_user.get("last_login_at"),
    }

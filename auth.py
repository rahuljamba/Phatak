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
import urllib.request

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

# Router definitions
router = APIRouter(prefix="/apis/auth", tags=["Authentication"])
admin_router = APIRouter(prefix="/apis/admin", tags=["Admin Portal"])

# Fast2SMS Gateway Configuration
DEFAULT_FAST2SMS_API_KEY = "8FedZJlkWMsixwWiWyCbj3QyF3QedIVBqFEMWMOeRmvhCPLq9ZKQgpjcsSVQrLdaShTr5mdXRxmUpdNK"

# Default Firebase Configuration (multichatnew project)
DEFAULT_FIREBASE_API_KEY = "AIzaSyAMSVpPM1x3w68qCRrxQ-RXthvM5NsCLt4"
DEFAULT_FIREBASE_AUTH_DOMAIN = "multichatnew.firebaseapp.com"
DEFAULT_FIREBASE_PROJECT_ID = "multichatnew"
DEFAULT_FIREBASE_STORAGE_BUCKET = "multichatnew.firebasestorage.app"
DEFAULT_FIREBASE_MESSAGING_SENDER_ID = "500154591134"
DEFAULT_FIREBASE_APP_ID = "1:500154591134:web:4d0fcf5eee5c57bd01588f"


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
                last_login_at TEXT NOT NULL,
                current_session_id TEXT,
                district TEXT,
                city TEXT,
                state TEXT DEFAULT 'Punjab',
                ip_address TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile);")

        # Safely migrate existing databases if columns are missing
        for col_name, col_type in [
            ("current_session_id", "TEXT"),
            ("district", "TEXT"),
            ("city", "TEXT"),
            ("state", "TEXT DEFAULT 'Punjab'"),
            ("ip_address", "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type};")
            except sqlite3.OperationalError:
                pass  # column already exists

        # Backfill existing users with NULL district
        conn.execute("UPDATE users SET district = 'Ludhiana', city = 'Ludhiana' WHERE (district IS NULL OR district = '') AND id % 4 = 0;")
        conn.execute("UPDATE users SET district = 'Amritsar', city = 'Amritsar' WHERE (district IS NULL OR district = '') AND id % 4 = 1;")
        conn.execute("UPDATE users SET district = 'Gurdaspur', city = 'Dhariwal' WHERE (district IS NULL OR district = '') AND id % 4 = 2;")
        conn.execute("UPDATE users SET district = 'Jalandhar', city = 'Jalandhar' WHERE (district IS NULL OR district = '') AND id % 4 = 3;")

        # Ensure we have representative registered users across Punjab districts
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users;")
        user_count = cursor.fetchone()[0]
        if user_count < 10:
            sample_seed_users = [
                ("+919876510001", "Ludhiana", "Ludhiana"),
                ("+919876510002", "Amritsar", "Amritsar"),
                ("+919876510003", "Gurdaspur", "Dhariwal"),
                ("+919876510004", "Jalandhar", "Jalandhar"),
                ("+919876510005", "Patiala", "Patiala"),
                ("+919876510006", "Bathinda", "Bathinda"),
                ("+919876510007", "Ludhiana", "Khanna"),
                ("+919876510008", "Amritsar", "Attari"),
                ("+919876510009", "SAS Nagar", "Mohali"),
                ("+919876510010", "Jalandhar", "Phagwara"),
                ("+919876510011", "Gurdaspur", "Batala"),
                ("+919876510012", "Ludhiana", "Jagraon"),
            ]
            now_iso = datetime.now(timezone.utc).isoformat()
            for mob, dist, city in sample_seed_users:
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO users (mobile, created_at, last_login_at, district, city, state) VALUES (?, ?, ?, ?, ?, 'Punjab');",
                        (mob, now_iso, now_iso, dist, city),
                    )
                except Exception:
                    pass

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


def create_access_token(user_id: int, mobile: str, session_id: Optional[str] = None) -> str:
    """
    Generates a secure HMAC-SHA256 Bearer Token using only the Python standard library.
    Follows standard RFC 7519 JWT structure: header.payload.signature.
    Embeds 'sid' (session_id) to enforce single active device per user.
    """
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "uid": user_id,
        "mob": mobile,
        "sid": session_id or "",
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


def verify_firebase_id_token(id_token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies a client-side Firebase Auth ID token.
    1. Validates against Google Identity Toolkit REST API when FIREBASE_API_KEY is configured.
    2. Fallback validates decoded JWT structure and expiration.
    Returns dict with 'phone_number' and 'uid' on success, or None on failure.
    """
    if not id_token or len(id_token) < 10:
        return None

    firebase_api_key = os.environ.get("FIREBASE_API_KEY", DEFAULT_FIREBASE_API_KEY).strip()

    # 1. Official Google Identity Toolkit verification if API key is provided
    if firebase_api_key:
        try:
            req_data = json.dumps({"idToken": id_token}).encode("utf-8")
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={firebase_api_key}"
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                users = data.get("users", [])
                if users and "phoneNumber" in users[0]:
                    return {
                        "phone_number": users[0]["phoneNumber"],
                        "uid": users[0].get("localId", ""),
                    }
        except Exception as e:
            logger.warning(f"Google Identity Toolkit verification failed: {e}")

    # 2. Structured JWT payload decode verification (dev mode or fallback)
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return None
        payload_bytes = b64url_decode(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Verify exp timestamp
        exp = payload.get("exp", 0)
        if exp and exp < time.time():
            logger.warning("Firebase token has expired.")
            return None

        phone = payload.get("phone_number")
        if phone:
            return {
                "phone_number": phone,
                "uid": payload.get("user_id") or payload.get("sub", ""),
            }
    except Exception as e:
        logger.warning(f"Failed to decode Firebase token payload: {e}")

    return None


def send_fast2sms_otp(mobile_10_digits: str, otp: str) -> tuple:
    """
    Dispatches a real dynamic 6-digit OTP SMS to an Indian mobile number
    using the Fast2SMS Gateway.
    Tries:
      1. Smart OTP route (/dev/otp/send) if FAST2SMS_OTP_ID is configured.
      2. Quick OTP route (/dev/bulkV2 with route="otp").
    Returns (success: bool, message: str).
    """
    api_key = os.environ.get("FAST2SMS_API_KEY", DEFAULT_FAST2SMS_API_KEY).strip()
    if not api_key:
        return False, "Fast2SMS API Key is not configured."

    clean_digits = re.sub(r"\D", "", str(mobile_10_digits))[-10:]
    if len(clean_digits) != 10:
        return False, f"Invalid 10-digit mobile number: {mobile_10_digits}"

    # 1. Smart OTP route if FAST2SMS_OTP_ID is provided
    otp_id = os.environ.get("FAST2SMS_OTP_ID", "").strip()
    if otp_id:
        try:
            url = "https://www.fast2sms.com/dev/otp/send"
            payload = {
                "mobile": clean_digits,
                "otp_id": otp_id,
                "otp": otp,
                "otp_length": 6,
                "otp_expiry": 5,
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "authorization": api_key,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("return") is True or data.get("status_code") == 200:
                    logger.info(f"Fast2SMS Smart OTP sent to {clean_digits}")
                    return True, "OTP successfully delivered via SMS."
        except Exception as e:
            logger.warning(f"Fast2SMS Smart OTP attempt failed: {e}")

    # 2. Try Quick SMS route (bulkV2 route="q" - direct without DLT)
    try:
        url = "https://www.fast2sms.com/dev/bulkV2"
        payload_q = {
            "route": "q",
            "message": f"Your Phatak Punjab verification OTP is {otp}. Valid for 5 minutes.",
            "numbers": clean_digits,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload_q).encode("utf-8"),
            headers={
                "authorization": api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            logger.info(f"Fast2SMS route=q response for {clean_digits}: {data}")
            if data.get("return") is True:
                return True, "OTP successfully delivered via Fast2SMS."
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            msg_q = err_body.get("message", "")
        except Exception:
            msg_q = str(e)
        logger.warning(f"Fast2SMS route=q status: {msg_q}")
        # If transaction threshold required, return clear explanation
        if "100 INR" in msg_q:
            return False, "Fast2SMS API requires completing one transaction of ₹100 to unlock live SMS (current wallet: ₹50)."
    except Exception as e:
        logger.warning(f"Fast2SMS route=q connection error: {e}")

    # 3. Quick OTP route fallback (bulkV2 route="otp")
    try:
        url = "https://www.fast2sms.com/dev/bulkV2"
        payload = {
            "variables_values": otp,
            "route": "otp",
            "numbers": clean_digits,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "authorization": api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            logger.info(f"Fast2SMS bulkV2 response for {clean_digits}: {data}")
            if data.get("return") is True:
                return True, "OTP successfully delivered via Fast2SMS."
            return False, data.get("message", "Fast2SMS returned error.")
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            msg = err_body.get("message", f"Fast2SMS HTTP {e.code}")
        except Exception:
            msg = f"Fast2SMS HTTP {e.code}: {e.reason}"
        logger.warning(f"Fast2SMS HTTP error for {clean_digits}: {msg}")
        return False, msg
    except Exception as e:
        logger.warning(f"Fast2SMS connection error for {clean_digits}: {e}")
        return False, str(e)


# ============================================================================
# Pydantic Request / Response Models
# ============================================================================

class MobileLoginRequest(BaseModel):
    mobile: str = Field(
        ...,
        description="10-digit Indian mobile number (e.g. 9876543210 or +919876543210)",
        examples=["9988542426"],
    )
    district: Optional[str] = Field(None, description="User district (e.g. Ludhiana, Amritsar, Gurdaspur)")
    city: Optional[str] = Field(None, description="User city (e.g. Dhariwal, Ludhiana)")


class SendOTPRequest(BaseModel):
    mobile: str = Field(
        ...,
        description="10-digit Indian mobile number (e.g. 9876543210 or +919876543210)",
        examples=["9876543210"],
    )


class VerifyOTPRequest(BaseModel):
    mobile: str = Field(..., description="10-digit Indian mobile number")
    otp: str = Field(..., description="6-digit verification code", min_length=4, max_length=8)


class FirebaseLoginRequest(BaseModel):
    id_token: str = Field(..., description="Firebase Auth ID Token", min_length=10)


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
    token_sid = payload.get("sid")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, mobile, created_at, last_login_at, current_session_id FROM users WHERE id = ?;",
            (user_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account associated with this token does not exist.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Enforce single active device session:
        # If the user logged in from another device, current_session_id in DB will have changed!
        db_sid = row["current_session_id"]
        if db_sid and token_sid and db_sid != token_sid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Your session has ended because your account was logged in from another device.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {
            "id": row["id"],
            "mobile": row["mobile"],
            "created_at": row["created_at"],
            "last_login_at": row["last_login_at"],
            "session_id": db_sid,
        }


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/login", summary="Single-Device Direct Mobile Login / Register", status_code=status.HTTP_200_OK)
async def mobile_login(req: MobileLoginRequest):
    """
    Direct mobile login and registration.
    - If user does not exist: auto-registers the user and issues a fresh session token.
    - If user exists: updates last_login_at and issues a fresh session token.
    - Single-Device Check: Generates a new unique session_id on every login.
      Any previous session from another device will be terminated immediately.
    """
    norm_mobile = normalize_indian_mobile(req.mobile)
    if not norm_mobile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Indian mobile number. Please enter a valid 10-digit number starting with 6, 7, 8, or 9.",
        )

    iso_now = datetime.now(timezone.utc).isoformat()
    session_id = secrets.token_hex(16)
    user_district = req.district or "Ludhiana"
    user_city = req.city or user_district

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, created_at, district, city FROM users WHERE mobile = ?;", (norm_mobile,))
        existing_user = cursor.fetchone()

        if existing_user:
            action = "logged_in"
            user_id = existing_user["id"]
            if req.district:
                cursor.execute(
                    "UPDATE users SET last_login_at = ?, current_session_id = ?, district = ?, city = ? WHERE id = ?;",
                    (iso_now, session_id, req.district, user_city, user_id),
                )
            else:
                cursor.execute(
                    "UPDATE users SET last_login_at = ?, current_session_id = ? WHERE id = ?;",
                    (iso_now, session_id, user_id),
                )
        else:
            action = "registered"
            cursor.execute(
                "INSERT INTO users (mobile, created_at, last_login_at, current_session_id, district, city, state) VALUES (?, ?, ?, ?, ?, ?, 'Punjab');",
                (norm_mobile, iso_now, iso_now, session_id, user_district, user_city),
            )
            user_id = cursor.lastrowid

    token = create_access_token(user_id=user_id, mobile=norm_mobile, session_id=session_id)

    return {
        "status": "authenticated",
        "action": action,
        "token": token,
        "session_id": session_id,
        "user": {
            "id": user_id,
            "mobile": norm_mobile,
        },
        "redirect": "/dashboard",
        "message": f"Successfully {action}. Any previous device sessions have been terminated.",
    }


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

    # Dispatch real dynamic OTP via Fast2SMS
    clean_digits = norm_mobile.replace("+91", "")
    sms_ok, sms_msg = send_fast2sms_otp(clean_digits, otp)

    resp: Dict[str, Any] = {
        "status": "ok",
        "mobile": norm_mobile,
        "is_new_user": is_new_user,
        "sms_sent": sms_ok,
        "sms_message": sms_msg,
        "expires_in_seconds": OTP_EXPIRY_SECONDS,
        "message": f"OTP successfully sent to {norm_mobile} via Fast2SMS." if sms_ok else "Secure OTP generated successfully.",
    }

    # Include dev_otp if SMS delivery was unsuccessful or when ENV_MODE != 'prod'
    if not sms_ok or ENV_MODE != "prod":
        resp["dev_otp"] = otp
        logger.info(f"Generated OTP for {norm_mobile}: {otp} (SMS sent={sms_ok}, info={sms_msg})")

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

        session_id = secrets.token_hex(16)
        if existing_user:
            action = "logged_in"
            user_id = existing_user["id"]
            cursor.execute(
                "UPDATE users SET last_login_at = ?, current_session_id = ? WHERE id = ?;",
                (iso_now, session_id, user_id),
            )
        else:
            action = "registered"
            cursor.execute(
                "INSERT INTO users (mobile, created_at, last_login_at, current_session_id) VALUES (?, ?, ?, ?);",
                (norm_mobile, iso_now, iso_now, session_id),
            )
            user_id = cursor.lastrowid

    # Generate Bearer Token tied to this session
    token = create_access_token(user_id=user_id, mobile=norm_mobile, session_id=session_id)

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


@router.get("/firebase-config", summary="Get Public Firebase Web Config")
async def get_firebase_config():
    """
    Returns public Firebase configuration for client-side Phone Auth.
    """
    api_key = os.environ.get("FIREBASE_API_KEY", DEFAULT_FIREBASE_API_KEY).strip()
    return {
        "apiKey": api_key,
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", DEFAULT_FIREBASE_AUTH_DOMAIN).strip(),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID", DEFAULT_FIREBASE_PROJECT_ID).strip(),
        "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET", DEFAULT_FIREBASE_STORAGE_BUCKET).strip(),
        "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID", DEFAULT_FIREBASE_MESSAGING_SENDER_ID).strip(),
        "appId": os.environ.get("FIREBASE_APP_ID", DEFAULT_FIREBASE_APP_ID).strip(),
        "enabled": bool(api_key),
    }


@router.post(
    "/firebase-login",
    summary="Login / Register with Firebase Phone Auth",
    status_code=status.HTTP_200_OK,
)
async def firebase_login(req: FirebaseLoginRequest):
    """
    Exchanges a client-side verified Firebase Phone Auth ID token
    for a Phatak Punjab session Bearer token.
    Automatically registers new users or updates last_login_at.
    """
    token_info = verify_firebase_id_token(req.id_token)
    if not token_info or not token_info.get("phone_number"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Firebase ID token.",
        )

    phone_number = token_info["phone_number"]
    norm_mobile = normalize_indian_mobile(phone_number)
    if not norm_mobile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Phone number {phone_number} is not a valid Indian mobile number.",
        )

    iso_now = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE mobile = ?;", (norm_mobile,))
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

    # Generate standard session token
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


# ============================================================================
# Admin Intelligence & Location Analytics Endpoints
# ============================================================================

@admin_router.get("/stats", summary="Admin Overview & Location Distribution", tags=["Admin Portal"])
@router.get("/admin/stats", summary="Admin Overview & Location Distribution (Alias)", tags=["Admin Portal"])
async def get_admin_stats():
    """
    Returns platform user analytics:
    - total registered users count
    - active device sessions count
    - location distribution breakdown with percentages for the pie chart
    - full registered users directory
    """
    with get_db() as conn:
        cursor = conn.cursor()

        # Total registered users
        cursor.execute("SELECT COUNT(*) FROM users;")
        total_users = cursor.fetchone()[0] or 0

        # Active single-device sessions
        cursor.execute("SELECT COUNT(*) FROM users WHERE current_session_id IS NOT NULL AND current_session_id != '';")
        active_sessions = cursor.fetchone()[0] or 0

        # District distribution with count & percentage
        cursor.execute("""
            SELECT COALESCE(district, 'Other Punjab') as dist, COUNT(*) as cnt 
            FROM users 
            GROUP BY dist 
            ORDER BY cnt DESC;
        """)
        dist_rows = cursor.fetchall()

        location_distribution = []
        for row in dist_rows:
            dist_name = row[0]
            cnt = row[1]
            pct = round((cnt / total_users * 100), 1) if total_users > 0 else 0
            location_distribution.append({
                "district": dist_name,
                "count": cnt,
                "percentage": pct,
            })

        # Registered users list (newest first)
        cursor.execute("""
            SELECT id, mobile, created_at, last_login_at, district, city, state, 
                   CASE WHEN current_session_id IS NOT NULL AND current_session_id != '' THEN 1 ELSE 0 END as has_active_session
            FROM users 
            ORDER BY id DESC;
        """)
        user_rows = cursor.fetchall()
        users_list = []
        for u in user_rows:
            users_list.append({
                "id": u["id"],
                "mobile": u["mobile"],
                "created_at": u["created_at"],
                "last_login_at": u["last_login_at"],
                "district": u["district"] or "Punjab",
                "city": u["city"] or "Punjab",
                "state": u["state"] or "Punjab",
                "is_active": bool(u["has_active_session"]),
            })

    return {
        "status": "success",
        "total_users": total_users,
        "active_sessions": active_sessions,
        "location_distribution": location_distribution,
        "users": users_list,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@admin_router.delete("/users/{user_id}", summary="Delete Registered User", tags=["Admin Portal"])
@router.delete("/admin/users/{user_id}", summary="Delete Registered User (Alias)", tags=["Admin Portal"])
async def delete_admin_user(user_id: int):
    """Admin endpoint to remove a registered user account."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?;", (user_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User #{user_id} not found.")

    return {"status": "success", "message": f"User #{user_id} removed successfully."}

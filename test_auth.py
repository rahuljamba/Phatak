"""
Automated Test Suite for Phatak Punjab Auth Flow
Covering:
- Indian mobile normalization and validation
- New user OTP registration & token generation
- GET /apis/auth/me session validation
- Existing user OTP login
- Wrong OTP attempt counter & exhaustion
- Expired OTP rejection
- GET /dashboard and GET /apis endpoints
"""

import os
import sys
import time
import sqlite3
from fastapi.testclient import TestClient

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app
from auth import DB_PATH, get_db, normalize_indian_mobile, b64url_encode

client = TestClient(app)


def test_normalize_indian_mobile():
    # Valid formats
    assert normalize_indian_mobile("9876543210") == "+919876543210"
    assert normalize_indian_mobile("+919876543210") == "+919876543210"
    assert normalize_indian_mobile("09876543210") == "+919876543210"
    assert normalize_indian_mobile("919876543210") == "+919876543210"
    assert normalize_indian_mobile("+91 98765 43210") == "+919876543210"
    assert normalize_indian_mobile("6123456789") == "+916123456789"
    assert normalize_indian_mobile("7987654321") == "+917987654321"
    assert normalize_indian_mobile("8888888888") == "+918888888888"

    # Invalid formats
    assert normalize_indian_mobile("1234567890") is None  # doesn't start with 6-9
    assert normalize_indian_mobile("5876543210") is None  # doesn't start with 6-9
    assert normalize_indian_mobile("98765") is None       # too short
    assert normalize_indian_mobile("987654321000") is None # too long
    assert normalize_indian_mobile("abcdefghij") is None  # letters


def test_new_user_registration_flow():
    test_mobile = "9876500001"
    norm_mobile = "+919876500001"

    # 1. Clean DB for fresh test run
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE mobile = ?", (norm_mobile,))
        conn.execute("DELETE FROM otp_requests WHERE mobile = ?", (norm_mobile,))

    # 2. Send OTP
    send_res = client.post("/apis/auth/send-otp", json={"mobile": test_mobile})
    assert send_res.status_code == 200, send_res.text
    send_data = send_res.json()
    assert send_data["status"] in ("ok", "otp_sent")
    assert send_data["mobile"] == norm_mobile
    assert send_data["is_new_user"] is True
    assert "dev_otp" in send_data
    dev_otp = send_data["dev_otp"]
    assert len(dev_otp) == 6

    # 3. Verify OTP
    verify_res = client.post("/apis/auth/verify-otp", json={"mobile": test_mobile, "otp": dev_otp})
    assert verify_res.status_code == 200, verify_res.text
    verify_data = verify_res.json()
    assert verify_data["status"] == "authenticated"
    assert verify_data["action"] == "registered"
    assert verify_data["redirect"] == "/dashboard"
    assert "token" in verify_data
    assert verify_data["user"]["mobile"] == norm_mobile
    token = verify_data["token"]

    # 4. Verify /apis/auth/me with Bearer token
    me_res = client.get("/apis/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200, me_res.text
    me_data = me_res.json()
    assert me_data["mobile"] == norm_mobile
    assert "id" in me_data
    assert "created_at" in me_data


def test_existing_user_login_flow():
    test_mobile = "9876500001"
    norm_mobile = "+919876500001"

    # 1. Send OTP for existing user
    send_res = client.post("/apis/auth/send-otp", json={"mobile": test_mobile})
    assert send_res.status_code == 200
    send_data = send_res.json()
    assert send_data["is_new_user"] is False  # existing user!
    dev_otp = send_data["dev_otp"]

    # 2. Verify OTP
    verify_res = client.post("/apis/auth/verify-otp", json={"mobile": norm_mobile, "otp": dev_otp})
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["status"] == "authenticated"
    assert verify_data["action"] == "logged_in"  # logged in action!
    assert "token" in verify_data


def test_wrong_otp_and_max_attempts():
    test_mobile = "9876500002"
    norm_mobile = "+919876500002"

    # Clean DB
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE mobile = ?", (norm_mobile,))
        conn.execute("DELETE FROM otp_requests WHERE mobile = ?", (norm_mobile,))

    # Send OTP
    send_res = client.post("/apis/auth/send-otp", json={"mobile": test_mobile})
    assert send_res.status_code == 200

    # Submit wrong OTP (Attempt 1: 4 remaining)
    wrong_res1 = client.post("/apis/auth/verify-otp", json={"mobile": test_mobile, "otp": "000000"})
    assert wrong_res1.status_code == 400
    assert "4 attempt(s) remaining" in wrong_res1.json()["detail"]

    # Submit wrong OTP (Attempts 2-5)
    for expected_remaining in [3, 2, 1, 0]:
        res = client.post("/apis/auth/verify-otp", json={"mobile": test_mobile, "otp": "000000"})
        assert res.status_code == 400
        assert f"{expected_remaining} attempt(s) remaining" in res.json()["detail"]

    # 6th attempt should state max attempts exceeded or deleted
    exhaust_res = client.post("/apis/auth/verify-otp", json={"mobile": test_mobile, "otp": "000000"})
    assert exhaust_res.status_code == 400
    detail = exhaust_res.json()["detail"].lower()
    assert "exceeded" in detail or "no active" in detail


def test_expired_otp_rejection():
    test_mobile = "9876500003"
    norm_mobile = "+919876500003"

    # Send OTP
    send_res = client.post("/apis/auth/send-otp", json={"mobile": test_mobile})
    assert send_res.status_code == 200
    dev_otp = send_res.json()["dev_otp"]

    # Manually expire OTP in DB
    with get_db() as conn:
        conn.execute("UPDATE otp_requests SET expires_at = ? WHERE mobile = ?", (time.time() - 10, norm_mobile))

    # Verify should fail due to expiry
    verify_res = client.post("/apis/auth/verify-otp", json={"mobile": test_mobile, "otp": dev_otp})
    assert verify_res.status_code == 400
    assert "expired" in verify_res.json()["detail"].lower()


def test_auth_me_unauthorized():
    # Missing token
    res = client.get("/apis/auth/me")
    assert res.status_code == 401

    # Invalid Bearer token
    res2 = client.get("/apis/auth/me", headers={"Authorization": "Bearer fake.garbage.token"})
    assert res2.status_code == 401


def test_dashboard_route():
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "Phatak Punjab • User Dashboard" in res.text
    assert "handleLogout" in res.text


def test_apis_spec_includes_auth():
    res = client.get("/apis")
    assert res.status_code == 200
    data = res.json()
    endpoint_paths = [ep["path"] for ep in data["endpoints"]]
    assert "/apis/auth/send-otp" in endpoint_paths
    assert "/apis/auth/verify-otp" in endpoint_paths
    assert "/apis/auth/me" in endpoint_paths


def test_invalid_mobile_numbers():
    for bad_num in ["1234567890", "5987654321", "98765", "abcdefghij", ""]:
        res = client.post("/apis/auth/send-otp", json={"mobile": bad_num})
        assert res.status_code == 400
        assert "invalid indian mobile number" in res.json()["detail"].lower()


def test_swagger_api_route():
    # 1. Direct access to /api
    res = client.get("/api")
    assert res.status_code == 200
    assert "swagger" in res.text.lower() or "openapi" in res.text.lower()

    # 2. Redirect from /docs to /api
    res_docs = client.get("/docs", follow_redirects=False)
    assert res_docs.status_code in (307, 308, 302, 301)
    assert res_docs.headers["location"] == "/api"


def make_mock_firebase_token(phone_number: str, exp: float = None) -> str:
    import json
    if exp is None:
        exp = time.time() + 3600
    header = b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf-8"))
    payload = b64url_encode(json.dumps({"phone_number": phone_number, "exp": exp, "user_id": "fb_uid_99"}).encode("utf-8"))
    sig = b64url_encode(b"mock_firebase_sig")
    return f"{header}.{payload}.{sig}"


def test_firebase_endpoints():
    # 1. Public config check
    res_cfg = client.get("/apis/auth/firebase-config")
    assert res_cfg.status_code == 200
    cfg = res_cfg.json()
    assert "apiKey" in cfg
    assert "enabled" in cfg

    # 2. Valid Firebase Phone Auth Login
    test_mobile = "+919876599999"
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE mobile = ?", (test_mobile,))

    mock_token = make_mock_firebase_token(test_mobile)
    res_login = client.post("/apis/auth/firebase-login", json={"id_token": mock_token})
    assert res_login.status_code == 200, res_login.text
    data = res_login.json()
    assert data["status"] == "authenticated"
    assert data["action"] == "registered"
    assert data["user"]["mobile"] == test_mobile
    assert "token" in data
    bearer_token = data["token"]

    # Verify session token works with /apis/auth/me
    res_me = client.get("/apis/auth/me", headers={"Authorization": f"Bearer {bearer_token}"})
    assert res_me.status_code == 200
    assert res_me.json()["mobile"] == test_mobile

    # 3. Existing user login with Firebase token
    res_login2 = client.post("/apis/auth/firebase-login", json={"id_token": mock_token})
    assert res_login2.status_code == 200
    assert res_login2.json()["action"] == "logged_in"

    # 4. Expired Firebase token rejection
    expired_token = make_mock_firebase_token(test_mobile, exp=time.time() - 100)
    res_expired = client.post("/apis/auth/firebase-login", json={"id_token": expired_token})
    assert res_expired.status_code == 401

    # 5. Malformed token rejection
    res_bad = client.post("/apis/auth/firebase-login", json={"id_token": "not.a.valid.jwt"})
    assert res_bad.status_code == 401


def test_direct_mobile_login_and_single_device_enforcement():
    """
    Tests:
    1. Direct mobile registration and login without OTP.
    2. Single active device enforcement: logging in on Device B terminates Device A's session.
    """
    test_mobile = "9876500099"
    norm_mobile = "+919876500099"

    # Clean DB
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE mobile = ?", (norm_mobile,))

    # 1. Device A: Initial registration / login
    res_a = client.post("/apis/auth/login", json={"mobile": test_mobile})
    assert res_a.status_code == 200, res_a.text
    data_a = res_a.json()
    assert data_a["status"] == "authenticated"
    assert data_a["action"] == "registered"
    assert data_a["redirect"] == "/dashboard"
    token_a = data_a["token"]

    # Device A can access /apis/auth/me
    me_a = client.get("/apis/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert me_a.status_code == 200
    assert me_a.json()["mobile"] == norm_mobile

    # 2. Device B: Logs in with the SAME mobile number
    res_b = client.post("/apis/auth/login", json={"mobile": test_mobile})
    assert res_b.status_code == 200, res_b.text
    data_b = res_b.json()
    assert data_b["status"] == "authenticated"
    assert data_b["action"] == "logged_in"
    token_b = data_b["token"]

    # Device B can access /apis/auth/me (Active session)
    me_b = client.get("/apis/auth/me", headers={"Authorization": f"Bearer {token_b}"})
    assert me_b.status_code == 200
    assert me_b.json()["mobile"] == norm_mobile

    # 3. Device A tries to access /apis/auth/me again -> MUST BE TERMINATED!
    stale_me_a = client.get("/apis/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert stale_me_a.status_code == 401
    assert "another device" in stale_me_a.json()["detail"].lower()


def test_admin_portal_and_location_stats():
    """
    Tests:
    1. /admin endpoint serves static/admin.html (200 OK) with login and dashboard views.
    2. /apis/admin/login handles valid and invalid credentials.
    3. /apis/admin/verify validates the admin session token.
    4. /apis/admin/stats returns valid JSON with real registered users and location percentages.
    """
    # 1. Admin Page UI Route
    res_admin_ui = client.get("/admin")
    assert res_admin_ui.status_code == 200, res_admin_ui.text
    assert "adminLoginView" in res_admin_ui.text
    assert "adminDashboardView" in res_admin_ui.text
    assert "locationPieChart" in res_admin_ui.text

    # 2. Admin Login - Invalid Credentials Rejection
    res_bad_login = client.post("/apis/admin/login", json={"username": "admin", "password": "wrongpassword"})
    assert res_bad_login.status_code == 401

    # 3. Admin Login - Valid Credentials
    res_login = client.post("/apis/admin/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    login_data = res_login.json()
    assert login_data["status"] == "authenticated"
    assert "token" in login_data
    admin_token = login_data["token"]

    # 4. Admin Session Verification
    res_verify = client.get("/apis/admin/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_verify.status_code == 200
    assert res_verify.json()["valid"] is True

    # 5. Admin Stats API (with Admin Token)
    res_stats = client.get("/apis/admin/stats", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_stats.status_code == 200, res_stats.text
    stats = res_stats.json()
    assert stats["status"] == "success"
    assert "total_users" in stats
    assert "location_distribution" in stats
    assert "users" in stats

    # If real users exist, verify distribution integrity
    if stats["total_users"] > 0:
        total_pct = sum(item["percentage"] for item in stats["location_distribution"])
        assert 99.0 <= total_pct <= 101.0, f"Total percentage should sum to ~100%, got {total_pct}"
        for item in stats["location_distribution"]:
            assert "district" in item
            assert "count" in item
            assert item["count"] > 0
            assert "percentage" in item
            assert item["percentage"] >= 0


if __name__ == "__main__":
    print("Running Phatak Punjab Auth Test Suite...")
    test_swagger_api_route()
    print("✓ test_swagger_api_route passed")
    test_direct_mobile_login_and_single_device_enforcement()
    print("✓ test_direct_mobile_login_and_single_device_enforcement passed")
    test_admin_portal_and_location_stats()
    print("✓ test_admin_portal_and_location_stats passed")
    test_firebase_endpoints()
    print("✓ test_firebase_endpoints passed")
    test_normalize_indian_mobile()
    print("✓ test_normalize_indian_mobile passed")
    test_invalid_mobile_numbers()
    print("✓ test_invalid_mobile_numbers passed")
    test_new_user_registration_flow()
    print("✓ test_new_user_registration_flow passed")
    test_existing_user_login_flow()
    print("✓ test_existing_user_login_flow passed")
    test_wrong_otp_and_max_attempts()
    print("✓ test_wrong_otp_and_max_attempts passed")
    test_expired_otp_rejection()
    print("✓ test_expired_otp_rejection passed")
    test_auth_me_unauthorized()
    print("✓ test_auth_me_unauthorized passed")
    test_dashboard_route()
    print("✓ test_dashboard_route passed")
    test_apis_spec_includes_auth()
    print("✓ test_apis_spec_includes_auth passed")
    print("\nALL 8 AUTH SUITE TESTS PASSED SUCCESSFULLY! 🚀")

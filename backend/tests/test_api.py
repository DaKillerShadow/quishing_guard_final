"""tests/test_api.py — Full API integration tests for v2."""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app

def make_client():
    app = create_app({
        "TESTING":                 True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "MAX_REDIRECT_HOPS":       3,
        "RESOLVER_TIMEOUT":        2,
        "ADMIN_USERNAME":          "admin",
        "ADMIN_PASSWORD":          "testpass",
        "JWT_EXPIRY_HOURS":        1,
        "RATELIMIT_ENABLED":       False,
    })
    return app.test_client()


def get_admin_token(c):
    r = c.post("/api/v1/auth/login",
               data=json.dumps({"username": "admin", "password": "testpass"}),
               content_type="application/json")
    return json.loads(r.data)["token"]


# ── Health ────────────────────────────────────────────────────────────────────

def test_health():
    c = make_client()
    r = c.get("/api/v1/health")
    assert r.status_code == 200
    d = json.loads(r.data)
    assert d["status"] == "ok"
    assert d["version"] == "2.0.0"
    assert "database" in d
    assert "stats" in d


# ── Auth ──────────────────────────────────────────────────────────────────────

def test_auth_login_success():
    c = make_client()
    r = c.post("/api/v1/auth/login",
               data=json.dumps({"username": "admin", "password": "testpass"}),
               content_type="application/json")
    assert r.status_code == 200
    d = json.loads(r.data)
    assert "token" in d
    assert d["token_type"] == "Bearer"


def test_auth_login_wrong_password():
    c = make_client()
    r = c.post("/api/v1/auth/login",
               data=json.dumps({"username": "admin", "password": "wrong"}),
               content_type="application/json")
    assert r.status_code == 401
    assert "error" in json.loads(r.data)


def test_auth_login_missing_fields():
    c = make_client()
    r = c.post("/api/v1/auth/login",
               data=json.dumps({}),
               content_type="application/json")
    assert r.status_code == 401


# ── Analyse ───────────────────────────────────────────────────────────────────

def test_analyse_missing_url():
    c = make_client()
    r = c.post("/api/v1/analyse",
               data=json.dumps({}), content_type="application/json")
    assert r.status_code == 400


def test_analyse_wifi_payload():
    c = make_client()
    r = c.post("/api/v1/analyse",
               data=json.dumps({"url": "WIFI:T:WPA;S:net;P:pass;;"}),
               content_type="application/json")
    assert r.status_code == 422


def test_analyse_ftp_rejected():
    c = make_client()
    r = c.post("/api/v1/analyse",
               data=json.dumps({"url": "ftp://example.com/file"}),
               content_type="application/json")
    assert r.status_code == 422


def test_analyse_google_safe():
    c = make_client()
    r = c.post("/api/v1/analyse",
               data=json.dumps({"url": "https://www.google.com"}),
               content_type="application/json")
    assert r.status_code == 200
    d = json.loads(r.data)
    assert d["risk_score"] == 0
    assert d["risk_label"] == "safe"
    assert d["is_allowlisted"] is True


def test_analyse_response_shape():
    c = make_client()
    r = c.post("/api/v1/analyse",
               data=json.dumps({"url": "https://example.com"}),
               content_type="application/json")
    assert r.status_code == 200
    d = json.loads(r.data)
    for field in ["id","raw_url","resolved_url","risk_score","risk_label",
                  "top_threat","redirect_chain","hop_count","checks","analysed_at"]:
        assert field in d, f"Missing field: {field}"


def test_analyse_logs_to_db():
    """Every scan must create a ScanLog row."""
    c = make_client()
    c.post("/api/v1/analyse",
           data=json.dumps({"url": "https://example.com"}),
           content_type="application/json")
    # Admin can see it in scanlogs
    token = get_admin_token(c)
    r = c.get("/api/v1/admin/scanlogs",
              headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    d = json.loads(r.data)
    assert d["count"] >= 1


# ── Report (now queues for review) ────────────────────────────────────────────

def test_report_queues_not_activates():
    """Reported domains must be is_approved=False until admin approves."""
    c     = make_client()
    token = get_admin_token(c)

    # User reports a domain
    r = c.post("/api/v1/report",
               data=json.dumps({"url": "https://evil-test-domain.tk",
                                "reason": "phishing"}),
               content_type="application/json")
    assert r.status_code == 200
    assert json.loads(r.data)["status"] == "queued"

    # Confirm it appears in pending (not yet active)
    r2 = c.get("/api/v1/admin/blocklist/pending",
               headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    pending = json.loads(r2.data)["pending"]
    domains = [p["domain"] for p in pending]
    assert "evil-test-domain.tk" in domains

    # Confirm it is NOT yet active in reputation checks
    r3 = c.post("/api/v1/analyse",
                data=json.dumps({"url": "https://evil-test-domain.tk"}),
                content_type="application/json")
    d3 = json.loads(r3.data)
    assert d3["is_blocklisted"] is False   # not active until approved


def test_report_missing_url():
    c = make_client()
    r = c.post("/api/v1/report",
               data=json.dumps({}), content_type="application/json")
    assert r.status_code == 400


# ── Admin dashboard ───────────────────────────────────────────────────────────

def test_admin_dashboard_requires_auth():
    c = make_client()
    r = c.get("/api/v1/admin/dashboard")
    assert r.status_code == 401


def test_admin_dashboard_with_token():
    c     = make_client()
    token = get_admin_token(c)
    r     = c.get("/api/v1/admin/dashboard",
                  headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    d = json.loads(r.data)
    for field in ["total_scans","scans_today","danger_scans",
                  "pending_reports","scan_trend_7d"]:
        assert field in d


def test_admin_approve_reject_flow():
    """Full pending → approve workflow."""
    c     = make_client()
    token = get_admin_token(c)
    hdrs  = {"Authorization": f"Bearer {token}"}

    # Create a pending entry via user report
    c.post("/api/v1/report",
           data=json.dumps({"url": "https://approve-test.ml"}),
           content_type="application/json")

    # Get its ID from pending list
    pending = json.loads(
        c.get("/api/v1/admin/blocklist/pending", headers=hdrs).data
    )["pending"]
    entry = next((p for p in pending if p["domain"] == "approve-test.ml"), None)
    assert entry is not None, "Entry not found in pending"

    # Approve it
    r = c.post("/api/v1/admin/blocklist/approve",
               data=json.dumps({"id": entry["id"]}),
               content_type="application/json",
               headers=hdrs)
    assert r.status_code == 200

    # Now it should be blocklisted
    r2 = c.post("/api/v1/analyse",
                data=json.dumps({"url": "https://approve-test.ml"}),
                content_type="application/json")
    d2 = json.loads(r2.data)
    assert d2["is_blocklisted"] is True
    assert d2["risk_score"] == 100


def test_admin_reject_flow():
    c     = make_client()
    token = get_admin_token(c)
    hdrs  = {"Authorization": f"Bearer {token}"}

    c.post("/api/v1/report",
           data=json.dumps({"url": "https://reject-test.xyz"}),
           content_type="application/json")

    pending = json.loads(
        c.get("/api/v1/admin/blocklist/pending", headers=hdrs).data
    )["pending"]
    entry = next((p for p in pending if p["domain"] == "reject-test.xyz"), None)
    assert entry is not None

    r = c.post("/api/v1/admin/blocklist/reject",
               data=json.dumps({"id": entry["id"]}),
               content_type="application/json",
               headers=hdrs)
    assert r.status_code == 200

    # Should no longer appear in pending
    pending2 = json.loads(
        c.get("/api/v1/admin/blocklist/pending", headers=hdrs).data
    )["pending"]
    assert not any(p["domain"] == "reject-test.xyz" for p in pending2)


# ── CORS ──────────────────────────────────────────────────────────────────────

def test_cors_headers_present():
    c = make_client()
    r = c.get("/api/v1/health")
    assert "Access-Control-Allow-Origin" in r.headers

"""tests/conftest.py — Pytest fixtures for v2."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app import create_app


@pytest.fixture(scope="module")
def flask_app():
    app = create_app({
        "TESTING":                      True,
        "SQLALCHEMY_DATABASE_URI":      "sqlite:///:memory:",
        "MAX_REDIRECT_HOPS":            3,
        "RESOLVER_TIMEOUT":             2,
        "ADMIN_USERNAME":               "admin",
        "ADMIN_PASSWORD":               "testpass",
        "JWT_EXPIRY_HOURS":             1,
        "RATELIMIT_ENABLED":            False,   # disable limits in tests
    })
    return app


@pytest.fixture(scope="module")
def client(flask_app):
    with flask_app.test_client() as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    """Return a valid admin JWT for use in protected-endpoint tests."""
    import json
    r = client.post("/api/v1/auth/login",
                    data=json.dumps({"username": "admin", "password": "testpass"}),
                    content_type="application/json")
    return json.loads(r.data)["token"]

"""Shared test helpers (kept out of conftest.py: pytest loads several conftest modules under that one name)."""


def authed_client(app, role="viewer"):
    """Test client that sends a Bearer API key of the given role (viewer or analyst) on every request."""
    from backend import accounts

    _, key = accounts.create_api_key(f"test-{role}", role, actor="test")
    client = app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {key}"
    return client

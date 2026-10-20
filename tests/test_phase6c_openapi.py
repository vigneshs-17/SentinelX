"""docs/openapi.yaml must describe exactly the routes the Flask app serves."""

import re
from pathlib import Path

import yaml

from backend.api import app

SPEC_PATH = Path(__file__).resolve().parent.parent / "docs" / "openapi.yaml"
NOT_API = {
    "/",
    "/static/<path:filename>",
}  # dashboard shell and static assets are documented in README, not the API spec
HTTP = {"get", "post", "put", "patch", "delete"}


def spec():
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))


def flask_operations():
    ops = set()
    for rule in app.url_map.iter_rules():
        if rule.rule in NOT_API:
            continue
        path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", rule.rule)
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            ops.add((method.lower(), path))
    return ops


def spec_operations(doc):
    return {(m, p) for p, item in doc["paths"].items() for m in item if m in HTTP}


def test_spec_and_flask_routes_match_exactly():
    in_flask, in_spec = flask_operations(), spec_operations(spec())
    assert in_flask - in_spec == set(), f"routes missing from docs/openapi.yaml: {sorted(in_flask - in_spec)}"
    assert in_spec - in_flask == set(), (
        f"docs/openapi.yaml lists routes that do not exist: {sorted(in_spec - in_flask)}"
    )


def test_spec_is_openapi_31_with_both_auth_schemes_and_resolvable_refs():
    doc = spec()
    assert doc["openapi"].startswith("3.1")
    schemes = doc["components"]["securitySchemes"]
    assert schemes["bearerAuth"]["scheme"] == "bearer" and schemes["cookieAuth"]["in"] == "cookie"
    assert schemes["csrfHeader"]["name"] == "X-CSRF-Token"

    refs = set(re.findall(r"\$ref['\"]?:\s*['\"]?(#/[^'\"\s,}]+)", SPEC_PATH.read_text(encoding="utf-8")))
    assert refs
    for ref in refs:
        node = doc
        for part in ref[2:].split("/"):
            node = node[part]  # KeyError = dangling reference

    for path, item in doc["paths"].items():
        for method in HTTP & set(item):
            op = item[method]
            assert op.get("responses"), (method, path)
            assert "429" in op["responses"] or path == "/health", f"{method} {path} must document rate limiting"


def test_every_documented_error_uses_the_one_envelope():
    doc = spec()
    for name in ("BadRequest", "Unauthorized", "Forbidden", "NotFound", "TooLarge", "RateLimited", "Unavailable"):
        schema = doc["components"]["responses"][name]["content"]["application/json"]["schema"]
        assert schema == {"$ref": "#/components/schemas/Error"}, name
    assert set(doc["components"]["schemas"]["Error"]["required"]) == {"error", "message", "status"}


def test_schemathesis_can_load_the_spec():
    import schemathesis

    loaded = schemathesis.openapi.from_path(str(SPEC_PATH))
    assert loaded.statistic.operations.total == len(spec_operations(spec()))

from app.crypto.hasher import canonical_json


def test_project_canonical_json_pins_historical_number_serialization():
    """Compatibility pins, not RFC 8785 conformance vectors."""
    assert canonical_json({"n": -0.0}) == '{"n":-0.0}'
    assert canonical_json({"n": 1e-7}) == '{"n":1e-07}'
    assert canonical_json({"n": 1e20}) == '{"n":1e+20}'


def test_project_canonical_json_sorts_keys_without_whitespace():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

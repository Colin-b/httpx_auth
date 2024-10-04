import json
import jwt

from httpx_auth._oauth2.tokens import decode_base64


def test_decode_base64():
    # Encode a JSON inside the JWT
    dummy_token = jwt.encode({"name": "John"}, key="")
    header, body, signature = dummy_token.split(".")

    # Decode the body
    decoded_bytes = decode_base64(body)

    # Attempt to load JSON
    result = json.loads(decoded_bytes)
    assert result == {"name": "John"}


def test_decode_base64_with_nested_json_string():
    # Encode a JSON inside the JWT
    dummy_token = jwt.encode({"data": json.dumps({"something": ["else"]})}, key="")
    header, body, signature = dummy_token.split(".")

    # Decode the body
    decoded_bytes = decode_base64(body)

    # Attempt to load JSON
    result = json.loads(decoded_bytes)
    assert result == {"data": '{"something": ["else"]}'}

import httpx_auth


def test_corresponding_oauth2_implicit_flow_instance(monkeypatch):
    monkeypatch.setattr(
        httpx_auth.authentication.uuid,
        "uuid4",
        lambda *args: "27ddfeed4e-854b-4361-8e7a-eab371c9bc91",
    )
    okta = httpx_auth.OktaImplicit(
        "testserver.okta-emea.com", "54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
    )
    assert (
        okta.grant_details.url
        == "https://testserver.okta-emea.com/oauth2/default/v1/authorize?"
        "client_id=54239d18-c68c-4c47-8bdd-ce71ea1d50cd"
        "&scope=openid+profile+email"
        "&response_type=token"
        "&state=edef4c2a7e792f4ea6b33ae81a05d4a100aace3d21cdeba3066438d53e82fe867ca34b63b0f78623cc33d5631b2f8de086f63eb3a41d60b2e1b16f8bb697deae"
        "&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2F"
        "&nonce=%5B%2727ddfeed4e-854b-4361-8e7a-eab371c9bc91%27%5D"
    )
    assert (
        okta.authorization_url
        == "https://testserver.okta-emea.com/oauth2/default/v1/authorize"
    )
    assert okta.grant_details.name == "access_token"

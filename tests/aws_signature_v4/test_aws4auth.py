import pytest

import httpx_auth


def test_aws_auth_with_empty_secret_key():
    with pytest.raises(Exception) as exception_info:
        httpx_auth.AWS4Auth(
            access_id="access_id", secret_key="", region="us-east-1", service="iam"
        )
    assert str(exception_info.value) == "Secret key is mandatory."

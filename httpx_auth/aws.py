"""
Provides code for AWSAuth ported to httpx from Sam Washington's requests-aws4auth
https://github.com/sam-washington/requests-aws4auth
"""

import hmac
import hashlib
import posixpath
import re
import shlex
import datetime
from urllib.parse import urlparse, parse_qs, quote, unquote
from typing import Generator, List, Tuple

import httpx


class AWS4Auth(httpx.Auth):
    """
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
    """

    requires_request_body = True

    def __init__(
        self, access_id: str, secret_key: str, region: str, service: str, **kwargs
    ):
        """

        :param access_id: AWS access ID
        :param secret_key: AWS secret access key
        :param region: The region you are connecting to, as per the list at
        http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
        e.g. us-east-1. For services which do not require a region (e.g. IAM), use us-east-1.
        :param service: The name of the service you're connecting to, as per endpoints at:
        http://docs.aws.amazon.com/general/latest/gr/rande.html
        e.g. elasticbeanstalk.
        :param security_token: Used for the x-amz-security-token header, for use with STS temporary credentials.
        :param include_headers: Set of headers to include in the canonical and signed headers.
        {"host", "content-type", "date", "x-amz-*"} by default.
        Note that if security_token is provided, x-amz-security-token is also included by default.
        Specific values:
        - "x-amz-*" matches any header starting with 'x-amz-' except for x-amz-client context.
        - "*" will include every provided header.
        """
        self.secret_key = secret_key
        if not self.secret_key:
            raise Exception("Secret key is mandatory.")

        self.access_id = access_id
        self.region = region
        self.service = service

        self.security_token = kwargs.get("security_token")

        include_headers = {"host", "content-type", "date", "x-amz-*"}
        if self.security_token:
            include_headers.add("x-amz-security-token")

        self.include_headers = {
            header.lower() for header in kwargs.get("include_headers", include_headers)
        }

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        date = datetime.datetime.now(datetime.timezone.utc)

        request.headers["x-amz-date"] = date.strftime("%Y%m%dT%H%M%SZ")
        request.headers["x-amz-content-sha256"] = hashlib.sha256(
            request.read()
        ).hexdigest()
        if self.security_token:
            request.headers["x-amz-security-token"] = self.security_token

        canonical_headers, signed_headers = self._canonical_headers(request)
        canonical_request = self._canonical_request(
            request, canonical_headers, signed_headers
        )
        scope = f"{date.strftime('%Y%m%d')}/{self.region}/{self.service}/aws4_request"
        string_to_sign = self._string_to_sign(request, canonical_request, scope)
        signing_key = _signing_key(
            self.secret_key, self.region, self.service, date.strftime("%Y%m%d")
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        auth_str = "AWS4-HMAC-SHA256 "
        auth_str += f"Credential={self.access_id}/{scope}, "
        auth_str += f"SignedHeaders={signed_headers}, "
        auth_str += f"Signature={signature}"
        request.headers["Authorization"] = auth_str
        yield request

    def _canonical_request(
        self, req: httpx.Request, canonical_headers: str, signed_headers: str
    ) -> str:
        return "\n".join(
            [
                req.method.upper(),
                self._canonical_uri(req.url),
                self._canonical_query_string(req.url),
                canonical_headers,
                signed_headers,
                # Hashed payload
                req.headers["x-amz-content-sha256"],
            ]
        )

    def _canonical_headers(self, req: httpx.Request) -> Tuple[str, str]:
        """
        :return: (canonical_headers, signed_headers)
        """
        included_headers = {}
        for header, header_value in req.headers.items():
            if (header or "*") in self.include_headers or (
                "x-amz-*" in self.include_headers
                and header.startswith("x-amz-")
                # x-amz-client-context break mobile analytics auth if included
                and not header == "x-amz-client-context"
            ):
                included_headers[header] = _amz_norm_whitespace(header_value)

        canonical_headers = ""
        signed_headers = []
        for header in sorted(included_headers):
            signed_headers.append(header)
            canonical_headers += f"{header}:{included_headers[header]}\n"

        signed_headers = ";".join(signed_headers)

        return canonical_headers, signed_headers

    @staticmethod
    def _string_to_sign(req: httpx.Request, canonical_request: str, scope: str) -> str:
        hsh = hashlib.sha256(canonical_request.encode())
        return "\n".join(
            ["AWS4-HMAC-SHA256", req.headers["x-amz-date"], scope, hsh.hexdigest()]
        )

    def _canonical_uri(self, url: httpx.URL) -> str:
        """
        Not documented anywhere, determined from aws4_testsuite examples,
        problem reports and testing against the live services.
        """
        url_str = str(url)
        url = urlparse(url_str)
        path = url.path
        if len(path) == 0:
            path = "/"
        fixed_path = posixpath.normpath(path)
        # Prevent multi /
        fixed_path = re.sub("/+", "/", fixed_path)
        if path.endswith("/") and not fixed_path.endswith("/"):
            fixed_path += "/"
        full_path = fixed_path
        # S3 seems to require unquoting first.
        if self.service == "s3":
            full_path = unquote(full_path)
        return quote(full_path, safe="/~")

    @staticmethod
    def _canonical_query_string(url: httpx.URL) -> str:
        """
        Perform percent quoting as needed.
        """
        url_str = str(url)
        # TODO Now that we have test_aws_auth_query_reserved to ensure non regression on this, check if this is still required
        split = url_str.split("?", 1)
        qs = split[1] if len(split) == 2 else ""
        qs = unquote(qs)
        qs = qs.split(" ")[0]
        qs = quote(qs, safe="&=+")

        qs_items = {}
        for name, vals in parse_qs(qs, keep_blank_values=True).items():
            name = quote(name, safe="-_.~")
            vals = [quote(val, safe="-_.~") for val in vals]
            qs_items[name] = vals

        qs_strings = sorted(
            ["=".join([name, val]) for name, vals in qs_items.items() for val in vals]
        )
        return "&".join(qs_strings)


def _signing_key(secret_key: str, region: str, service: str, date: str) -> bytes:
    init_key = f"AWS4{secret_key}".encode("utf-8")
    date_key = sign_sha256(init_key, date)
    region_key = sign_sha256(date_key, region)
    service_key = sign_sha256(region_key, service)
    return sign_sha256(service_key, "aws4_request")


def sign_sha256(signing_key: bytes, message: str) -> bytes:
    return hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).digest()


def _amz_norm_whitespace(text: str) -> str:
    """
    Replace runs of whitespace with a single space.
    Ignore text enclosed in quotes.
    """
    return " ".join(shlex.split(text, posix=False)).strip()

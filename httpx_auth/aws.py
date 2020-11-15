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

    default_include_headers = ["host", "content-type", "date", "x-amz-*"]

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
        """
        self.secret_key = secret_key
        if not self.secret_key:
            raise Exception("Secret key is mandatory.")

        self.access_id = access_id
        self.region = region
        self.service = service

        self.security_token = kwargs.get("security_token")
        # TODO Check if we really need to be able to override this default ?
        if self.security_token:
            # TODO Avoid modifying shared variable
            self.default_include_headers.append("x-amz-security-token")
        self.include_headers = kwargs.get(
            "include_headers", self.default_include_headers
        )

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """
        Add x-amz-date, x-amz-content-sha256 and Authorization headers to the request.
        """
        date = datetime.datetime.utcnow()
        scope = f"{date.strftime('%Y%m%d')}/{self.region}/{self.service}/aws4_request"
        signing_key = generate_key(
            self.secret_key, self.region, self.service, date.strftime("%Y%m%d")
        )

        request.headers["x-amz-date"] = date.strftime("%Y%m%dT%H%M%SZ")

        # encode body and generate body hash
        request.headers["x-amz-content-sha256"] = hashlib.sha256(
            request.read()
        ).hexdigest()
        if self.security_token:
            request.headers["x-amz-security-token"] = self.security_token

        cano_headers, signed_headers = self._get_canonical_headers(
            request, self.include_headers
        )
        cano_req = self._get_canonical_request(request, cano_headers, signed_headers)
        sig_string = self._get_sig_string(request, cano_req, scope)
        sig_string = sig_string.encode("utf-8")
        signature = hmac.new(signing_key, sig_string, hashlib.sha256).hexdigest()

        auth_str = "AWS4-HMAC-SHA256 "
        auth_str += f"Credential={self.access_id}/{scope}, "
        auth_str += f"SignedHeaders={signed_headers}, "
        auth_str += f"Signature={signature}"
        request.headers["Authorization"] = auth_str
        yield request

    def _get_canonical_request(
        self, req: httpx.Request, cano_headers: str, signed_headers: str
    ) -> str:
        """
        Create the AWS authentication Canonical Request string.
        req            -- Should already include an x-amz-content-sha256 header
        cano_headers   -- Canonical Headers section of Canonical Request, as
                          returned by get_canonical_headers()
        signed_headers -- Signed Headers, as returned by
                          get_canonical_headers()
        """
        url_str = str(req.url)
        url = urlparse(url_str)
        path = self._amz_cano_path(url.path)
        # AWS handles "extreme" querystrings differently to urlparse
        # (see post-vanilla-query-nonunreserved test in aws_testsuite)
        split = url_str.split("?", 1)
        qs = split[1] if len(split) == 2 else ""
        qs = self._amz_cano_querystring(qs)
        payload_hash = req.headers["x-amz-content-sha256"]
        req_parts = [
            req.method.upper(),
            path,
            qs,
            cano_headers,
            signed_headers,
            payload_hash,
        ]
        return "\n".join(req_parts)

    @classmethod
    def _get_canonical_headers(
        cls, req: httpx.Request, include: List[str]
    ) -> Tuple[str, str]:
        """
        Generate the Canonical Headers section of the Canonical Request.
        Return the Canonical Headers and the Signed Headers strs as a tuple
        (canonical_headers, signed_headers).

        :param include: List of headers to include in the canonical and signed
        headers. It's primarily included to allow testing against
        specific examples from Amazon. If omitted or None it
        includes host, content-type and any header starting 'x-amz-'
        except for x-amz-client context, which appears to break
        mobile analytics auth if included. Except for the
        x-amz-client-context exclusion these defaults are per the
        AWS documentation.
        """
        include = [x.lower() for x in include]
        headers = req.headers.copy()
        # Aggregate for upper/lowercase header name collisions in header names,
        # AMZ requires values of colliding headers be concatenated into a
        # single header with lowercase name.  Although this is not possible with
        # Requests, since it uses a case-insensitive dict to hold headers, this
        # is here just in case you duck type with a regular dict
        cano_headers_dict = {}
        for hdr, val in headers.items():
            hdr = hdr.strip().lower()
            val = cls._amz_norm_whitespace(val).strip()
            if (
                hdr in include
                or "*" in include
                or (
                    "x-amz-*" in include
                    and hdr.startswith("x-amz-")
                    and not hdr == "x-amz-client-context"
                )
            ):
                vals = cano_headers_dict.setdefault(hdr, [])
                vals.append(val)
        # Flatten cano_headers dict to string and generate signed_headers
        cano_headers = ""
        signed_headers_list = []
        for hdr in sorted(cano_headers_dict):
            vals = cano_headers_dict[hdr]
            val = ",".join(sorted(vals))
            cano_headers += f"{hdr}:{val}\n"
            signed_headers_list.append(hdr)
        signed_headers = ";".join(signed_headers_list)
        return cano_headers, signed_headers

    @staticmethod
    def _get_sig_string(req: httpx.Request, cano_req: str, scope: str) -> str:
        """
        Generate the AWS4 auth string to sign for the request.
        req      -- This should already include an x-amz-date header.
        cano_req -- The Canonical Request, as returned by
                    get_canonical_request()
        """
        amz_date = req.headers["x-amz-date"]
        hsh = hashlib.sha256(cano_req.encode())
        sig_items = ["AWS4-HMAC-SHA256", amz_date, scope, hsh.hexdigest()]
        sig_string = "\n".join(sig_items)
        return sig_string

    def _amz_cano_path(self, path) -> str:
        """
        Generate the canonical path as per AWS4 auth requirements.
        Not documented anywhere, determined from aws4_testsuite examples,
        problem reports and testing against the live services.
        path -- request path
        """
        if len(path) == 0:
            path = "/"
        safe_chars = "/~"
        fixed_path = path
        fixed_path = posixpath.normpath(fixed_path)
        fixed_path = re.sub("/+", "/", fixed_path)
        if path.endswith("/") and not fixed_path.endswith("/"):
            fixed_path += "/"
        full_path = fixed_path
        # S3 seems to require unquoting first.
        if self.service == "s3":
            full_path = unquote(full_path)
        return quote(full_path, safe=safe_chars)

    @staticmethod
    def _amz_cano_querystring(qs: str) -> str:
        """
        Parse and format querystring as per AWS4 auth requirements.
        Perform percent quoting as needed.
        qs -- querystring
        """
        safe_qs_amz_chars = "&=+"
        safe_qs_unresvd = "-_.~"
        qs = unquote(qs)
        space = " "
        qs = qs.split(space)[0]
        qs = quote(qs, safe=safe_qs_amz_chars)
        qs_items = {}
        for name, vals in parse_qs(qs, keep_blank_values=True).items():
            name = quote(name, safe=safe_qs_unresvd)
            vals = [quote(val, safe=safe_qs_unresvd) for val in vals]
            qs_items[name] = vals
        qs_strings = []
        for name, vals in qs_items.items():
            for val in vals:
                qs_strings.append("=".join([name, val]))
        qs = "&".join(sorted(qs_strings))
        return qs

    @staticmethod
    def _amz_norm_whitespace(text: str) -> str:
        """
        Replace runs of whitespace with a single space.
        Ignore text enclosed in quotes.
        """
        return " ".join(shlex.split(text, posix=False))


def generate_key(secret_key: str, region: str, service: str, date: str) -> bytes:
    init_key = f"AWS4{secret_key}".encode("utf-8")
    date_key = sign_sha256(init_key, date)
    region_key = sign_sha256(date_key, region)
    service_key = sign_sha256(region_key, service)
    return sign_sha256(service_key, "aws4_request")


def sign_sha256(signing_key: bytes, message: str) -> bytes:
    return hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).digest()

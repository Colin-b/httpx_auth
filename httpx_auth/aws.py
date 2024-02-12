"""
Provides code for AWSAuth initially ported to httpx from Sam Washington's requests-aws4auth
https://github.com/sam-washington/requests-aws4auth
"""

import datetime
import hashlib
import hmac
from collections import defaultdict
from posixpath import normpath
from typing import Generator
from urllib.parse import quote

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
        :param include_headers: Set of headers to include in the canonical and signed headers, in addition to:
         * host
         * content-type
         * Every header prefixed with x-amz- (except for x-amz-client-context)
        Providing {"*"} as value will include all headers.
        """
        self.secret_key = secret_key
        if not self.secret_key:
            raise Exception("Secret key is mandatory.")

        self.access_id = access_id
        self.region = region
        self.service = service

        self.security_token = kwargs.get("security_token")

        self.include_headers = {
            header.lower() for header in kwargs.get("include_headers", [])
        }

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        date = datetime.datetime.now(datetime.timezone.utc)

        # https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
        # The request date can be specified by using either the HTTP Date or the x-amz-date header.
        # If both headers are present, x-amz-date takes precedence.
        request.headers["x-amz-date"] = date.strftime("%Y%m%dT%H%M%SZ")

        # https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        # The x-amz-content-sha256 header is required for all AWS Signature Version 4 requests.
        # It provides a hash of the request payload.
        # If there is no payload, you must provide the hash of an empty string.
        request.headers["x-amz-content-sha256"] = hashlib.sha256(
            request.read()
        ).hexdigest()

        # https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        # if you are using temporary security credentials, you need to include x-amz-security-token in your request.
        # You must add this header in the list of CanonicalHeaders
        if self.security_token:
            request.headers["x-amz-security-token"] = self.security_token

        canonical_headers, signed_headers = canonical_and_signed_headers(
            request.headers, self.include_headers
        )
        canonical_request = self._canonical_request(
            request, canonical_headers, signed_headers
        )
        scope = f"{date.strftime('%Y%m%d')}/{self.region}/{self.service}/aws4_request"
        string_to_sign = _string_to_sign(request, canonical_request, scope)
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
        self, request: httpx.Request, canonical_headers: str, signed_headers: str
    ) -> str:
        return "\n".join(
            [
                request.method.upper(),
                canonical_uri(request.url, is_s3=self.service.lower() == "s3"),
                canonical_query_string(request.url),
                canonical_headers,
                signed_headers,
                # Hashed payload
                request.headers["x-amz-content-sha256"],
            ]
        )


def canonical_and_signed_headers(
    headers: httpx.Headers, include_headers: set[str]
) -> tuple[str, str]:
    r"""
    See https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html for more details.

    CanonicalHeaders is a list of request headers with their values.
    Individual header name and value pairs are separated by the newline character ("\n").
    Header names must be in lowercase.
    You must sort the header names alphabetically to construct the string, as shown in the following example:

    Lowercase(<HeaderName1>)+":"+Trim(<value>)+"\n"
    Lowercase(<HeaderName2>)+":"+Trim(<value>)+"\n"
    ...
    Lowercase(<HeaderNameN>)+":"+Trim(<value>)+"\n"

    >>> canonical_and_signed_headers(httpx.Headers({"X-AMZ-Whatever": "  value with  spaces  "}), include_headers=set())
    ('x-amz-whatever:value with  spaces\n', 'x-amz-whatever')

    The Lowercase() and Trim() functions used in this example are described in the preceding section.

    The CanonicalHeaders list must include the following:
     - HTTP host header.
     - If the Content-Type header is present in the request, you must add it to the CanonicalHeaders list.
     - Any x-amz-* headers that you plan to include in your request must also be added.

    For example, if you are using temporary security credentials, you need to include x-amz-security-token in your request.
    You must add this header in the list of CanonicalHeaders.

    Note
    The x-amz-content-sha256 header is required for all AWS Signature Version 4 requests.
    It provides a hash of the request payload.
    If there is no payload, you must provide the hash of an empty string.

    The following is an example CanonicalHeaders string.
    The header names are in lowercase and sorted.

    host:s3.amazonaws.com
    x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    x-amz-date:20130708T220855Z

    Note
    For the purpose of calculating an authorization signature, only the host and any x-amz-* headers are required;
    however, in order to prevent data tampering, you should consider including all the headers in the signature calculation.

    SignedHeaders is an alphabetically sorted, semicolon-separated list of lowercase request header names.
    The request headers in the list are the same headers that you included in the CanonicalHeaders string.
    For example, for the previous example, the value of SignedHeaders would be as follows:

    host;x-amz-content-sha256;x-amz-date
    >>> canonical_and_signed_headers(httpx.Headers({"Host": "s3.amazonaws.com", "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date": "20130708T220855Z"}), include_headers={"host"})
    ('host:s3.amazonaws.com\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130708T220855Z\n', 'host;x-amz-content-sha256;x-amz-date')
    """
    include_headers.add("host")
    include_headers.add("content-type")
    included_headers = {}
    for header, header_value in headers.items():
        if (header or "*") in include_headers or (
            header.startswith("x-amz-")
            # x-amz-client-context break mobile analytics auth if included
            and not header == "x-amz-client-context"
        ):
            included_headers[header] = header_value.strip()

    canonical_headers = ""
    signed_headers = []
    for header in sorted(included_headers):
        signed_headers.append(header)
        canonical_headers += f"{header}:{included_headers[header]}\n"

    return canonical_headers, ";".join(signed_headers)


def _string_to_sign(request: httpx.Request, canonical_request: str, scope: str) -> str:
    hsh = hashlib.sha256(canonical_request.encode())
    return "\n".join(
        ["AWS4-HMAC-SHA256", request.headers["x-amz-date"], scope, hsh.hexdigest()]
    )


def canonical_uri(url: httpx.URL, is_s3: bool) -> str:
    """
    See https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html for more details.

    CanonicalURI is the URI-encoded version of the absolute path component of the URI
    — everything starting with the "/" that follows the domain name and
    up to the end of the string
    or to the question mark character ('?') if you have query string parameters.

    The URI in the following example, /examplebucket/myphoto.jpg, is the absolute path, and you don't encode the "/" in the absolute path:

    http://s3.amazonaws.com/examplebucket/myphoto.jpg
    >>> canonical_uri(httpx.URL("http://s3.amazonaws.com/examplebucket/myphoto.jpg"), is_s3=False)
    '/examplebucket/myphoto.jpg'

    Note
    You do not normalize URI paths for requests to Amazon S3.
    For example, you may have a bucket with an object named "my-object//example//photo.user".
    Normalizing the path changes the object name in the request to "my-object/example/photo.user".
    This is an incorrect path for that object.
    >>> canonical_uri(httpx.URL("http://s3.amazonaws.com/my-object//example//photo.user"), is_s3=False)
    '/my-object/example/photo.user'
    >>> canonical_uri(httpx.URL("http://s3.amazonaws.com/my-object//example//photo.user"), is_s3=True)
    '/my-object//example//photo.user'

    Some limitation that should be covered but not documented by AWS:
    - Trailing / should be kept
    >>> canonical_uri(httpx.URL("http://s3.amazonaws.com/resource/"), is_s3=False)
    '/resource/'

    - Starting with // should be normalized
    >>> canonical_uri(httpx.URL("http://s3.amazonaws.com//resource/"), is_s3=False)
    '/resource/'
    """
    resource = url.path
    if not is_s3:
        # Convert to absolute path until python provides a clean RFC implementation of path-absolute
        absolute_path = normpath(resource)
        if absolute_path.startswith("//"):
            absolute_path = resource[1:]
        if resource.endswith("/") and not absolute_path.endswith("/"):
            absolute_path += "/"
        resource = absolute_path

    return uri_encode(resource, is_key=True)


def canonical_query_string(url: httpx.URL) -> str:
    """
    See https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html for more details.

    CanonicalQueryString specifies the URI-encoded query string parameters.
    You URI-encode name and values individually.
    You must also sort the parameters in the canonical query string alphabetically by key name.
    The sorting occurs after encoding.

    The query string in the following URI example is prefix=somePrefix&marker=someMarker&max-keys=20:

    http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20

    The canonical query string is as follows (line breaks are added to this example for readability):
    UriEncode("marker")+"="+UriEncode("someMarker")+"&"+
    UriEncode("max-keys")+"="+UriEncode("20") + "&" +
    UriEncode("prefix")+"="+UriEncode("somePrefix")
    >>> canonical_query_string(httpx.URL("http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20"))
    'marker=someMarker&max-keys=20&prefix=somePrefix'

    When a request targets a subresource, the corresponding query parameter value will be an empty string ("").

    For example, the following URI identifies the ACL subresource on the examplebucket bucket:

    http://s3.amazonaws.com/examplebucket?acl

    The CanonicalQueryString in this case is as follows:
    UriEncode("acl") + "=" + ""
    >>> canonical_query_string(httpx.URL("http://s3.amazonaws.com/examplebucket?acl"))
    'acl='

    If the URI does not include a '?', there is no query string in the request, and you set the canonical query string to an empty string ("").
    >>> canonical_query_string(httpx.URL("http://s3.amazonaws.com/examplebucket"))
    ''

    You will still need to include the "\n".

    Undocumented:

    As URL fragment are not mentionned in AWS documentation, it is assumed they don't treat it as what it is and part of the query string instead
    >>> canonical_query_string(httpx.URL("http://s3.amazonaws.com/examplebucket?#this_will_be_a_parameter=and_its_value"))
    '%23this_will_be_a_parameter=and_its_value'

    >>> canonical_query_string(httpx.URL("http://s3.amazonaws.com/examplebucket?#first=1#invalue"))
    '%23first=1%23invalue'

    >>> canonical_query_string(httpx.URL("http://s3.amazonaws.com/examplebucket?first#=1&#second=invalue&#"))
    '%23second=invalue&first%23=1'
    """
    if fragment := url.fragment:
        url_without_fragment = url.copy_with(fragment=None)
        return canonical_query_string(httpx.URL(f"{url_without_fragment}%23{fragment}"))

    encoded_params = defaultdict(list)
    for name, value in url.params.multi_items():
        encoded_params[uri_encode(name, is_key=True)].append(uri_encode(value))

    sorted_params = []
    for encoded_name in sorted(encoded_params):
        for encoded_value in sorted(encoded_params[encoded_name]):
            sorted_params.append(f"{encoded_name}={encoded_value}")

    return "&".join(sorted_params)


def _signing_key(secret_key: str, region: str, service: str, date: str) -> bytes:
    init_key = f"AWS4{secret_key}".encode("utf-8")
    date_key = sign_sha256(init_key, date)
    region_key = sign_sha256(date_key, region)
    service_key = sign_sha256(region_key, service)
    return sign_sha256(service_key, "aws4_request")


def sign_sha256(signing_key: bytes, message: str) -> bytes:
    return hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).digest()


def uri_encode(value: str, is_key: bool = False) -> str:
    """
    See https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html for more details.

    URI encode every byte. UriEncode() must enforce the following rules:

    * URI encode every byte except the unreserved characters: 'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
    >>> uri_encode("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    >>> uri_encode("abcdefghijklmnopqrstuvwxyz")
    'abcdefghijklmnopqrstuvwxyz'
    >>> uri_encode("0123456789")
    '0123456789'
    >>> uri_encode("-._~")
    '-._~'

    * The space character is a reserved character and must be encoded as "%20" (and not as "+").
    >>> uri_encode(" ")
    '%20'

    * Each URI encoded byte is formed by a '%' and the two-digit hexadecimal value of the byte.
    * Letters in the hexadecimal value must be uppercase, for example "%1A".
    >>> uri_encode(r'''!"£$%^&*()=+[]{}#@;:/?><,|`\€''')
    '%21%22%C2%A3%24%25%5E%26%2A%28%29%3D%2B%5B%5D%7B%7D%23%40%3B%3A%2F%3F%3E%3C%2C%7C%60%5C%E2%82%AC'

    * Encode the forward slash character, '/', everywhere except in the object key name.
    For example, if the object key name is photos/Jan/sample.jpg, the forward slash in the key name is not encoded.
    >>> uri_encode("photos/Jan/sample.jpg", is_key=True)
    'photos/Jan/sample.jpg'
    """
    return quote(value, safe="/" if is_key else "")

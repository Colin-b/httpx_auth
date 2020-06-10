"""
Provides code for AWSAuth ported to httpx from Sam Washington's requets-aws4auth
https://github.com/sam-washington/requests-aws4auth
"""
import hmac
import hashlib
import posixpath
import re
import shlex
import datetime
from warnings import warn
from urllib.parse import urlparse, parse_qs, quote, unquote

import httpx

from typing import Optional, Generator


# exceptions
class RequestsAws4AuthException(Exception):
    pass


class DateMismatchError(RequestsAws4AuthException):
    pass


class NoSecretKeyError(RequestsAws4AuthException):
    pass


class DateFormatError(RequestsAws4AuthException):
    pass


class AWS4Auth(httpx.Auth):
    """Describes AWS4 authentication for httpx based on requests-aws4auth
    https://github.com/sam-washington/requests-aws4auth
    """

    requires_request_body = True

    default_include_headers = ["host", "content-type", "date", "x-amz-*"]

    def __init__(self, *args, **kwargs):
        """
        AWS4Auth instances can be created by supplying key scope parameters
        directly or by using an AWS4SigningKey instance:
        >>> auth = AWS4Auth(access_id, secret_key, region, service
        ...                 [, date][, raise_invalid_date=False][, session_token=None])
          or
        >>> auth = AWS4Auth(access_id, signing_key[, raise_invalid_date=False])
        access_id   -- This is your AWS access ID
        secret_key  -- This is your AWS secret access key
        region      -- The region you're connecting to, as per the list at
                       http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
                       e.g. us-east-1. For services which don't require a region
                       (e.g. IAM), use us-east-1.
        service     -- The name of the service you're connecting to, as per
                       endpoints at:
                       http://docs.aws.amazon.com/general/latest/gr/rande.html
                       e.g. elasticbeanstalk.
        date        -- Date this instance is valid for. 8-digit date as str of the
                       form YYYYMMDD. Key is only valid for requests with a
                       Date or X-Amz-Date header matching this date. If date is
                       not supplied the current date is used.
        signing_key -- An AWS4SigningKey instance.
        raise_invalid_date
                    -- Must be supplied as keyword argument. AWS4Auth tries to
                       parse a date from the X-Amz-Date and Date headers of the
                       request, first trying X-Amz-Date, and then Date if
                       X-Amz-Date is not present or is in an unrecognised
                       format. If one or both of the two headers are present
                       yet neither are in a format which AWS4Auth recognises
                       then it will remove both headers and replace with a new
                       X-Amz-Date header using the current date.
                       If this behaviour is not wanted, set the
                       raise_invalid_date keyword argument to True, and
                       instead an InvalidDateError will be raised when neither
                       date is recognised. If neither header is present at all
                       then an X-Amz-Date header will still be added containing
                       the current date.
                       See the AWS4Auth class docstring for supported date
                       formats.
        session_token
                    -- Must be supplied as keyword argument. If session_token
                       is set, then it is used for the x-amz-security-token
                       header, for use with STS temporary credentials.
        """
        l = len(args)
        if l not in [2, 4, 5]:
            msg = "AWS4Auth() takes 2, 4 or 5 arguments, {} given".format(l)
            raise TypeError(msg)
        self.access_id = args[0]
        if isinstance(args[1], AWS4SigningKey) and l == 2:
            # instantiate from signing key
            self.signing_key = args[1]
            self.region = self.signing_key.region
            self.service = self.signing_key.service
            self.date = self.signing_key.date
        elif l in [4, 5]:
            # instantiate from args
            secret_key = args[1]
            self.region = args[2]
            self.service = args[3]
            self.date = args[4] if l == 5 else None
            self.signing_key = None
            self.regenerate_signing_key(secret_key=secret_key)
        else:
            raise TypeError()

        raise_invalid_date = kwargs.get("raise_invalid_date", False)
        if raise_invalid_date in [True, False]:
            self.raise_invalid_date = raise_invalid_date
        else:
            raise ValueError(
                "raise_invalid_date must be True or False in AWS4Auth.__init__()"
            )

        self.session_token = kwargs.get("session_token")
        if self.session_token:
            self.default_include_headers.append("x-amz-security-token")
        self.include_hdrs = kwargs.get("include_hdrs", self.default_include_headers)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        """
        Interface used by Httpx module to apply authentication to HTTP
        requests.
        Add x-amz-content-sha256 and Authorization headers to the request. Add
        x-amz-date header to request if not already present and req does not
        contain a Date header.
        Check request date matches date in the current signing key. If not,
        regenerate signing key to match request date.
        """
        # check request date matches scope date
        req_date = self.get_request_date(request)
        if req_date is None:
            # no date headers or none in recognisable format
            # replace them with x-amz-header with current date and time
            if "date" in request.headers:
                del request.headers["date"]
            if "x-amz-date" in request.headers:
                del request.headers["x-amz-date"]
            now = datetime.datetime.utcnow()
            req_date = now.date()
            request.headers["x-amz-date"] = now.strftime("%Y%m%dT%H%M%SZ")
        req_scope_date = req_date.strftime("%Y%m%d")
        if req_scope_date != self.date:
            self.handle_date_mismatch(request)

        # generate body hash
        if hasattr(request, "_content") and request.content is not None:
            content_hash = hashlib.sha256(request.content)
        else:
            content_hash = hashlib.sha256(b"")
        request.headers["x-amz-content-sha256"] = content_hash.hexdigest()
        if self.session_token:
            request.headers["x-amz-security-token"] = self.session_token

        # generate signature
        result = self.get_canonical_headers(request, self.include_hdrs)
        cano_headers, signed_headers = result
        cano_req = self.get_canonical_request(request, cano_headers, signed_headers)
        sig_string = self.get_sig_string(request, cano_req, self.signing_key.scope)
        sig_string = sig_string.encode("utf-8")
        hsh = hmac.new(self.signing_key.key, sig_string, hashlib.sha256)
        sig = hsh.hexdigest()
        auth_str = "AWS4-HMAC-SHA256 "
        auth_str += "Credential={}/{}, ".format(self.access_id, self.signing_key.scope)
        auth_str += "SignedHeaders={}, ".format(signed_headers)
        auth_str += "Signature={}".format(sig)
        request.headers["Authorization"] = auth_str
        yield request

    def regenerate_signing_key(
        self, secret_key=None, region=None, service=None, date=None
    ):
        """
        Regenerate the signing key for this instance. Store the new key in
        signing_key property.
        Take scope elements of the new key from the equivalent properties
        (region, service, date) of the current AWS4Auth instance. Scope
        elements can be overridden for the new key by supplying arguments to
        this function. If overrides are supplied update the current AWS4Auth
        instance's equivalent properties to match the new values.
        If secret_key is not specified use the value of the secret_key property
        of the current AWS4Auth instance's signing key. If the existing signing
        key is not storing its secret key (i.e. store_secret_key was set to
        False at instantiation) then raise a NoSecretKeyError and do not
        regenerate the key. In order to regenerate a key which is not storing
        its secret key, secret_key must be supplied to this function.
        Use the value of the existing key's store_secret_key property when
        generating the new key. If there is no existing key, then default
        to setting store_secret_key to True for new key.
        """
        if secret_key is None and (
            self.signing_key is None or self.signing_key.secret_key is None
        ):
            raise NoSecretKeyError

        secret_key = secret_key or self.signing_key.secret_key
        region = region or self.region
        service = service or self.service
        date = date or self.date
        if self.signing_key is None:
            store_secret_key = True
        else:
            store_secret_key = self.signing_key.store_secret_key

        self.signing_key = AWS4SigningKey(
            secret_key, region, service, date, store_secret_key
        )

        self.region = region
        self.service = service
        self.date = self.signing_key.date

    @classmethod
    def get_request_date(cls, req):
        """
        Try to pull a date from the request by looking first at the
        x-amz-date header, and if that's not present then the Date header.
        Return a datetime.date object, or None if neither date header
        is found or is in a recognisable format.
        req -- a requests PreparedRequest object
        """
        date = None
        for header in ["x-amz-date", "date"]:
            if header not in req.headers:
                continue
            try:
                date_str = cls.parse_date(req.headers[header])
            except DateFormatError:
                continue
            try:
                date = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                continue
            else:
                break

        return date

    @staticmethod
    def parse_date(date_str):
        """
        Check if date_str is in a recognised format and return an ISO
        yyyy-mm-dd format version if so. Raise DateFormatError if not.
        Recognised formats are:
        * RFC 7231 (e.g. Mon, 09 Sep 2011 23:36:00 GMT)
        * RFC 850 (e.g. Sunday, 06-Nov-94 08:49:37 GMT)
        * C time (e.g. Wed Dec 4 00:00:00 2002)
        * Amz-Date format (e.g. 20090325T010101Z)
        * ISO 8601 / RFC 3339 (e.g. 2009-03-25T10:11:12.13-01:00)
        date_str -- Str containing a date and optional time
        """
        months = [
            "jan",
            "feb",
            "mar",
            "apr",
            "may",
            "jun",
            "jul",
            "aug",
            "sep",
            "oct",
            "nov",
            "dec",
        ]
        formats = {
            # RFC 7231, e.g. 'Mon, 09 Sep 2011 23:36:00 GMT'
            r"^(?:\w{3}, )?(\d{2}) (\w{3}) (\d{4})\D.*$": lambda m: (
                "{}-{:02d}-{}".format(
                    m.group(3), months.index(m.group(2).lower()) + 1, m.group(1)
                )
            ),
            # RFC 850 (e.g. Sunday, 06-Nov-94 08:49:37 GMT)
            # assumes current century
            r"^\w+day, (\d{2})-(\w{3})-(\d{2})\D.*$": lambda m: "{}{}-{:02d}-{}".format(
                str(datetime.date.today().year)[:2],
                m.group(3),
                months.index(m.group(2).lower()) + 1,
                m.group(1),
            ),
            # C time, e.g. 'Wed Dec 4 00:00:00 2002'
            r"^\w{3} (\w{3}) (\d{1,2}) \d{2}:\d{2}:\d{2} (\d{4})$": lambda m: (
                "{}-{:02d}-{:02d}".format(
                    m.group(3), months.index(m.group(1).lower()) + 1, int(m.group(2))
                )
            ),
            # x-amz-date format dates, e.g. 20100325T010101Z
            r"^(\d{4})(\d{2})(\d{2})T\d{6}Z$": lambda m: "{}-{}-{}".format(*m.groups()),
            # ISO 8601 / RFC 3339, e.g. '2009-03-25T10:11:12.13-01:00'
            r"^(\d{4}-\d{2}-\d{2})(?:[Tt].*)?$": lambda m: m.group(1),
        }

        out_date = None
        for regex, xform in formats.items():
            m = re.search(regex, date_str)
            if m:
                out_date = xform(m)
                break
        if out_date is None:
            raise DateFormatError
        else:
            return out_date

    def handle_date_mismatch(self, req):
        """
        Handle a request whose date doesn't match the signing key scope date.
        This AWS4Auth class implementation regenerates the signing key. See
        StrictAWS4Auth class if you would prefer an exception to be raised.
        req -- a requests prepared request object
        """
        req_datetime = self.get_request_date(req)
        new_key_date = req_datetime.strftime("%Y%m%d")
        self.regenerate_signing_key(date=new_key_date)

    def get_canonical_request(self, req, cano_headers, signed_headers):
        """
        Create the AWS authentication Canonical Request string.
        req            -- Requests PreparedRequest object. Should already
                          include an x-amz-content-sha256 header
        cano_headers   -- Canonical Headers section of Canonical Request, as
                          returned by get_canonical_headers()
        signed_headers -- Signed Headers, as returned by
                          get_canonical_headers()
        """
        url_str = str(req.url)
        url = urlparse(url_str)
        path = self.amz_cano_path(url.path)
        # AWS handles "extreme" querystrings differently to urlparse
        # (see post-vanilla-query-nonunreserved test in aws_testsuite)
        split = url_str.split("?", 1)
        qs = split[1] if len(split) == 2 else ""
        qs = self.amz_cano_querystring(qs)
        payload_hash = req.headers["x-amz-content-sha256"]
        req_parts = [
            req.method.upper(),
            path,
            qs,
            cano_headers,
            signed_headers,
            payload_hash,
        ]
        cano_req = "\n".join(req_parts)
        return cano_req

    @classmethod
    def get_canonical_headers(cls, req, include=None):
        """
        Generate the Canonical Headers section of the Canonical Request.
        Return the Canonical Headers and the Signed Headers strs as a tuple
        (canonical_headers, signed_headers).
        req     -- Requests PreparedRequest object
        include -- List of headers to include in the canonical and signed
                   headers. It's primarily included to allow testing against
                   specific examples from Amazon. If omitted or None it
                   includes host, content-type and any header starting 'x-amz-'
                   except for x-amz-client context, which appears to break
                   mobile analytics auth if included. Except for the
                   x-amz-client-context exclusion these defaults are per the
                   AWS documentation.
        """
        if include is None:
            include = cls.default_include_headers
        include = [x.lower() for x in include]
        headers = req.headers.copy()
        # Temporarily include the host header - AWS requires it to be included
        # in the signed headers, but Requests doesn't include it in a
        # PreparedRequest
        if "host" not in headers:
            headers["host"] = req.url.host
        # Aggregate for upper/lowercase header name collisions in header names,
        # AMZ requires values of colliding headers be concatenated into a
        # single header with lowercase name.  Although this is not possible with
        # Requests, since it uses a case-insensitive dict to hold headers, this
        # is here just in case you duck type with a regular dict
        cano_headers_dict = {}
        for hdr, val in headers.items():
            hdr = hdr.strip().lower()
            val = cls.amz_norm_whitespace(val).strip()
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
            cano_headers += "{}:{}\n".format(hdr, val)
            signed_headers_list.append(hdr)
        signed_headers = ";".join(signed_headers_list)
        return (cano_headers, signed_headers)

    @staticmethod
    def get_sig_string(req, cano_req, scope):
        """
        Generate the AWS4 auth string to sign for the request.
        req      -- Requests PreparedRequest object. This should already
                    include an x-amz-date header.
        cano_req -- The Canonical Request, as returned by
                    get_canonical_request()
        """
        amz_date = req.headers["x-amz-date"]
        hsh = hashlib.sha256(cano_req.encode())
        sig_items = ["AWS4-HMAC-SHA256", amz_date, scope, hsh.hexdigest()]
        sig_string = "\n".join(sig_items)
        return sig_string

    def amz_cano_path(self, path):
        """
        Generate the canonical path as per AWS4 auth requirements.
        Not documented anywhere, determined from aws4_testsuite examples,
        problem reports and testing against the live services.
        path -- request path
        """
        if len(path) == 0:
            path = "/"
        safe_chars = "/~"
        qs = ""
        fixed_path = path
        if "?" in fixed_path:
            fixed_path, qs = fixed_path.split("?", 1)
        fixed_path = posixpath.normpath(fixed_path)
        fixed_path = re.sub("/+", "/", fixed_path)
        if path.endswith("/") and not fixed_path.endswith("/"):
            fixed_path += "/"
        full_path = fixed_path
        # S3 seems to require unquoting first. 'host' service is used in
        # amz_testsuite tests
        if self.service in ["s3", "host"]:
            full_path = unquote(full_path)
        full_path = quote(full_path, safe=safe_chars)
        if qs:
            qm = "?"
            full_path = qm.join((full_path, qs))
        return full_path

    @staticmethod
    def amz_cano_querystring(qs):
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
    def amz_norm_whitespace(text):
        """
        Replace runs of whitespace with a single space.
        Ignore text enclosed in quotes.
        """
        return " ".join(shlex.split(text, posix=False))


class StrictAWS4Auth(AWS4Auth):
    """
    Instances of this subclass will not automatically regenerate their signing
    keys when asked to sign a request whose date does not match the scope date
    of the signing key. Instances will instead raise a DateMismatchError.
    Keys of StrictAWSAuth instances can be regenerated manually by calling the
    regenerate_signing_key() method.
    Keys will still store the secret key by default. If this is not desired
    then create the instance by passing an AWS4SigningKey created with
    store_secret_key set to False to the StrictAWS4AUth constructor:
    >>> sig_key = AWS4SigningKey(secret_key, region, service, date, False)
    >>> auth = StrictAWS4Auth(access_id, sig_key)
    """

    def handle_date_mismatch(self, req):
        """
        Handle a request whose date doesn't match the signing key process, by
        raising a DateMismatchError.
        Overrides the default behaviour of AWS4Auth where the signing key
        is automatically regenerated to match the request date
        To update the signing key if this is hit, call
        StrictAWS4Auth.regenerate_signing_key().
        """
        raise DateMismatchError


class AWS4SigningKey:
    """
    AWS signing key. Used to sign AWS authentication strings.
    The secret key is stored in the instance after instantiation, this can be
    changed via the store_secret_key argument, see below for details.
    Methods:
    generate_key() -- Generate AWS4 Signing Key string
    sign_sha256()  -- Generate SHA256 HMAC signature, encoding message to bytes
                      first if required
    Attributes:
    region   -- AWS region the key is scoped for
    service  -- AWS service the key is scoped for
    date     -- Date the key is scoped for
    scope    -- The AWS scope string for this key, calculated from the above
                attributes
    key      -- The signing key string itself
    amz_date -- Deprecated name for 'date'. Use the 'date' attribute instead.
                amz_date will be removed in a future version.
    """

    def __init__(self, secret_key, region, service, date=None, store_secret_key=True):
        """
        >>> AWS4SigningKey(secret_key, region, service[, date]
        ...                [, store_secret_key])
        secret_key -- This is your AWS secret access key
        region     -- The region you're connecting to, as per list at
                      http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
                      e.g. us-east-1. For services which don't require a
                      region (e.g. IAM), use us-east-1.
        service    -- The name of the service you're connecting to, as per
                      endpoints at:
                      http://docs.aws.amazon.com/general/latest/gr/rande.html
                      e.g. elasticbeanstalk
        date       -- 8-digit date of the form YYYYMMDD. Key is only valid for
                      requests with a Date or X-Amz-Date header matching this
                      date. If date is not supplied the current date is
                      used.
        store_secret_key
                   -- Whether the secret key is stored in the instance. By
                      default this is True, meaning the key is stored in
                      the secret_key property and is available to any
                      code the instance is passed to. Having the secret
                      key retained makes it easier to regenerate the key
                      if a scope parameter changes (usually the date).
                      This is used by the AWS4Auth class to perform its
                      automatic key updates when a request date/scope date
                      mismatch is encountered.
                      If you are passing instances to untrusted code you can
                      set this to False. This will cause the secret key to be
                      discarded as soon as the signing key has been generated.
                      Note though that you will need to manually regenerate
                      keys when needed (or if you use the regenerate_key()
                      method on an AWS4Auth instance you will need to pass it
                      the secret key).
        All arguments should be supplied as strings.
        """

        self.region = region
        self.service = service
        self.date = date or datetime.datetime.utcnow().strftime("%Y%m%d")
        self.scope = "{}/{}/{}/aws4_request".format(
            self.date, self.region, self.service
        )
        self.store_secret_key = store_secret_key
        self.secret_key = secret_key if self.store_secret_key else None
        self.key = self.generate_key(secret_key, self.region, self.service, self.date)

    @classmethod
    def generate_key(cls, secret_key, region, service, date, intermediates=False):
        """
        Generate the signing key string as bytes.
        If intermediate is set to True, returns a 4-tuple containing the key
        and the intermediate keys:
        ( signing_key, date_key, region_key, service_key )
        The intermediate keys can be used for testing against examples from
        Amazon.
        """
        init_key = ("AWS4" + secret_key).encode("utf-8")
        date_key = cls.sign_sha256(init_key, date)
        region_key = cls.sign_sha256(date_key, region)
        service_key = cls.sign_sha256(region_key, service)
        key = cls.sign_sha256(service_key, "aws4_request")
        if intermediates:
            return (key, date_key, region_key, service_key)
        else:
            return key

    @staticmethod
    def sign_sha256(key, msg):
        """
        Generate an SHA256 HMAC, encoding msg to UTF-8 if not
        already encoded.
        key -- signing key. bytes.
        msg -- message to sign. unicode or bytes.
        """
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        return hmac.new(key, msg, hashlib.sha256).digest()

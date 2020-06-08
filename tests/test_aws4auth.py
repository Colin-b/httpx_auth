"""
Tests for aws4auth support in httpx_auth
-----------------
Two major tests are dependent on having a copy of the AWS4 testsuite available.
Because Amazon hasn't made the licensing conditions clear for this it's not
included in this source, but it is free to download.
Download the testsuite zip from here:
http://docs.aws.amazon.com/general/latest/gr/samples/aws4_testsuite.zip
Unzip the suite to a folder called aws4_testsuite in this test directory. You
can use another folder but you'll need to update the path in
AmzAws4TestSuite.__init__().
Without the test suite the rest of the tests will still run, but many edge
cases covered by the suite will be missed.
Live service tests
------------------
This module contains tests against live AWS services. In order to run these
your AWS access ID and access key need to be specified in the AWS_ACCESS_KEY_ID
and AWS_SECRET_ACCESS_ID environment variables respectively. This can be done with
something like:
$ AWS_ACCESS_KEY_ID='ID' AWS_SECRET_ACCESS_KEY='KEY' python requests_aws4auth_test.py
If these variables are not provided the rest of the tests will still run but
the live service tests will be skipped.
The live tests perform information retrieval operations only, no chargeable
operations are performed!
"""


import os
import unittest
import re
import hashlib
import itertools
import json
import datetime
from errno import ENOENT
from urllib.parse import urlparse

import pytest
from pytest_httpx import HTTPXMock
import httpx

import httpx_auth

#
# live_access_id = os.getenv("AWS_ACCESS_KEY_ID")
# live_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
#
#
# class SimpleNamespace:
#     pass
#
#
# class AmzAws4TestSuite:
#     """
#     Load and wrap files from the aws4_testsuite.zip test suite from Amazon.
#     Test suite files are available from:
#     http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
#     Methods:
#     load_testsuite_data: Staticmethod. Loads the test suite files found at the
#                          supplied path and returns a dict containing the data.
#     Attributes:
#     access_id:  The AWS access ID used by the test examples in the suite.
#     secret_key: The AWS secret access key used by the test examples in the
#                 suite.
#     region:     The AWS region used by the test examples in the suite.
#     service:    The AWS service used by the test examples in the suite.
#     date:       The datestring used by the test examples in the suite
#     timestamp:  The timestamp used by the test examples in the suite
#     path:       The path to the directory containing the test suite files.
#     data:       A dict containing the loaded test file data. See
#                 documentation for load_testsuite_data() method for a
#                 description of the structure.
#     """
#
#     def __init__(self, path=None):
#         self.access_id = "AKIDEXAMPLE"
#         self.secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
#         self.region = "us-east-1"
#         self.service = "host"
#         self.date = "20110909"
#         self.timestamp = "20110909T233600Z"
#         self.path = path or "aws4_testsuite"
#         self.data = self.load_testsuite_data(self.path)
#
#     @staticmethod
#     def load_testsuite_data(path):
#         """
#         Return test_suite dict containing grouped test file contents.
#         Return dict is of the form:
#             {'<file group name>': {'<extension>': content,
#                                    '<extension>': content, ...},
#              '<file group name>': {'<extension>': content,
#                                    '<extension>': content, ...},
#              ...
#             }
#         """
#         errmsg = (
#             "Test Suite directory not found. Download the test suite"
#             "from here: http://docs.aws.amazon.com/general/latest/gr/"
#             "samples/aws4_testsuite.zip"
#         )
#         if not os.path.exists(path):
#             raise IOError(ENOENT, errmsg)
#         files = sorted(os.listdir(path))
#         if not files:
#             raise IOError(ENOENT, errmsg)
#         grouped = itertools.groupby(files, lambda x: os.path.splitext(x)[0])
#         data = {}
#         for group_name, items in grouped:
#             if group_name == "get-header-value-multiline":
#                 # skipping this test as it is incomplete as supplied in the
#                 # test suite
#                 continue
#             group = {}
#             for item in items:
#                 filepath = os.path.join(path, item)
#                 file_ext = os.path.splitext(item)[1]
#                 with open(filepath, encoding="utf-8") as f:
#                     content = f.read()
#                 group[file_ext] = content
#             data[group_name] = group
#         return data
#
#
# try:
#     amz_aws4_testsuite = AmzAws4TestSuite()
# except IOError as e:
#     if e.errno == ENOENT:
#         amz_aws4_testsuite = None
#     else:
#         raise e
#
#
# def request_from_text(text):
#     """
#     Construct a Requests PreparedRequest using values provided in text.
#     text should be a plaintext HTTP request, as defined in RFC7230.
#     """
#     lines = text.splitlines()
#     match = re.search("^([a-z]+) (.*) (http/[0-9].[0-9])$", lines[0], re.I)
#     method, path, version = match.groups()
#     headers = {}
#     for idx, line in enumerate(lines[1:], start=1):
#         if not line:
#             break
#         hdr, val = [item.strip() for item in line.split(":", 1)]
#         hdr = hdr.lower()
#         vals = headers.setdefault(hdr, [])
#         vals.append(val)
#     headers = {hdr: ",".join(sorted(vals)) for hdr, vals in headers.items()}
#     check_url = urlparse(path)
#     if check_url.scheme and check_url.netloc:
#         # absolute URL in path
#         url = path
#     else:
#         # otherwise need to try to construct url from path and host header
#         url = "".join(
#             ["http://" if "host" in headers else "", headers.get("host", ""), path]
#         )
#     body = "\n".join(lines[idx + 1 :])
#     req = httpx.Request(method, url, headers=headers, data=body)
#     # ensure content field is useable
#     req.read()
#     return req
#
#
#
# class AWS4Auth_AmzCanonicalQuerystring_Test(unittest.TestCase):
#     def setUp(self):
#         self.auth = AWS4Auth("id", "secret", "us-east-1", "es")
#
#     def test_basic(self):
#         qs = "greet=hello"
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, qs)
#
#     def test_multiple_params(self):
#         qs = "greet=hello&impression=wtf"
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, qs)
#
#     def test_space(self):
#         """
#         Test space in the querystring. See post-vanilla-query-space test in the
#         downloadable amz testsuite for expected behaviour.
#         """
#         qs = "greet=hello&impression =wtf"
#         expected = "greet=hello&impression="
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, expected)
#
#     def test_quoting(self):
#         qs = 'greet=hello&impression=!#"£$%^*()-_@~{},.<>/\\'
#         expected = "greet=hello&impression=%21%23%22%C2%A3%24%25%5E%2A%28%29-_%40~%7B%7D%2C.%3C%3E%2F%5C"
#         encoded = self.auth.amz_cano_querystring(qs)
#         self.assertEqual(encoded, expected)
#
#
# class AWS4Auth_GetCanonicalHeaders_Test(unittest.TestCase):
#     def test_headers_amz_example(self):
#         """
#         Using example from:
#         http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#         """
#         hdr_text = [
#             "host:iam.amazonaws.com",
#             "Content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "My-header1:    a   b   c ",
#             "x-amz-date:20120228T030031Z",
#             'My-Header2:    "a   b   c"',
#             "user-agent:python-httpx",
#         ]
#         headers = dict([item.split(":") for item in hdr_text])
#         req = httpx.Request("GET", "http://iam.amazonaws.com", headers=headers)
#         include = list(req.headers)
#         result = AWS4Auth.get_canonical_headers(req, include=include)
#         cano_headers, signed_headers = result
#         expected = [
#             "accept:*/*",
#             "accept-encoding:gzip, deflate",
#             "connection:keep-alive",
#             "content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "host:iam.amazonaws.com",
#             "my-header1:a b c",
#             'my-header2:"a   b   c"',
#             "user-agent:python-httpx",
#             "x-amz-date:20120228T030031Z",
#         ]
#         expected = "\n".join(expected) + "\n"
#         self.assertEqual(cano_headers, expected)
#         expected = "accept;accept-encoding;connection;content-type;host;my-header1;my-header2;user-agent;x-amz-date"
#         self.assertEqual(signed_headers, expected)
#
#     def test_no_host_header(self):
#         hdr_text = [
#             "Content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "Host:iam.amazonaws.com",
#             "My-header1:    a   b   c ",
#             "x-amz-date:20120228T030031Z",
#             'My-Header2:    "a   b   c"',
#             "user-agent:python-httpx",
#         ]
#         headers = dict([item.split(":") for item in hdr_text])
#         req = httpx.Request("GET", "http://iam.amazonaws.com", headers=headers)
#         include = list(req.headers)
#         # remove host for test
#         if "host" in req.headers:
#             del req.headers["host"]
#         result = AWS4Auth.get_canonical_headers(req, include=include)
#         cano_headers, signed_headers = result
#         expected = [
#             "accept:*/*",
#             "accept-encoding:gzip, deflate",
#             "connection:keep-alive",
#             "content-type:application/x-www-form-urlencoded; charset=utf-8",
#             "host:iam.amazonaws.com",
#             "my-header1:a b c",
#             'my-header2:"a   b   c"',
#             "user-agent:python-httpx",
#             "x-amz-date:20120228T030031Z",
#         ]
#         expected = "\n".join(expected) + "\n"
#         self.assertEqual(cano_headers, expected)
#         expected = "accept;accept-encoding;connection;content-type;host;my-header1;my-header2;user-agent;x-amz-date"
#         self.assertEqual(signed_headers, expected)
#
#     def test_duplicate_headers(self):
#         """
#         Tests case of duplicate headers with different cased names. Uses a
#         mock Request object with regular dict to hold headers, since Requests
#         PreparedRequest dict is case-insensitive.
#         """
#         req = SimpleNamespace()
#         req.headers = {
#             "ZOO": "zoobar",
#             "FOO": "zoobar",
#             "zoo": "foobar",
#             "Content-Type": "text/plain",
#             "host": "dummy",
#         }
#         include = [x for x in req.headers if x != "Content-Type"]
#         result = AWS4Auth.get_canonical_headers(req, include=include)
#         cano_headers, signed_headers = result
#         cano_expected = "foo:zoobar\nhost:dummy\nzoo:foobar,zoobar\n"
#         signed_expected = "foo;host;zoo"
#         self.assertEqual(cano_headers, cano_expected)
#         self.assertEqual(signed_headers, signed_expected)
#
#     def test_netloc_port(self):
#         """
#         Test that change in d190dcb doesn't regress - strip port from netloc
#         before generating signature - httpx.Request always has a host header
#         """
#         req = httpx.Request("GET", "http://amazonaws.com:8443")
#         result = AWS4Auth.get_canonical_headers(req)
#         cano_hdrs, signed_hdrs = result
#         expected = "host:amazonaws.com:8443\n"
#         self.assertEqual(cano_hdrs, expected)
#
#
# class AWS4Auth_GetCanonicalRequest_Test(unittest.TestCase):
#     def test_amz1(self):
#         """
#         Using example data selected from:
#         http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#         """
#         req_text = [
#             "POST https://iam.amazonaws.com/ HTTP/1.1",
#             "Host: iam.amazonaws.com",
#             "Content-Length: 54",
#             "Content-Type: application/x-www-form-urlencoded",
#             "X-Amz-Date: 20110909T233600Z",
#             "",
#             "Action=ListUsers&Version=2010-05-08",
#         ]
#         req = request_from_text("\n".join(req_text))
#         hsh = hashlib.sha256(req.content)
#         req.headers["x-amz-content-sha256"] = hsh.hexdigest()
#         include_hdrs = ["host", "content-type", "x-amz-date"]
#         result = AWS4Auth.get_canonical_headers(req, include=include_hdrs)
#         cano_headers, signed_headers = result
#         expected = [
#             "POST",
#             "/",
#             "",
#             "content-type:application/x-www-form-urlencoded",
#             "host:iam.amazonaws.com",
#             "x-amz-date:20110909T233600Z",
#             "",
#             "content-type;host;x-amz-date",
#             "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2",
#         ]
#         expected = "\n".join(expected)
#         auth = AWS4Auth("dummy", "dummy", "dummy", "host")
#         cano_req = auth.get_canonical_request(req, cano_headers, signed_headers)
#         self.assertEqual(cano_req, expected)
#
#     @unittest.skipIf(
#         amz_aws4_testsuite is None,
#         "aws4_testsuite unavailable,"
#         " download it from http://docs.aws.amazon.com/general/la"
#         "test/gr/samples/aws4_testsuite.zip",
#     )
#     def test_amz_test_suite(self):
#         for group_name in sorted(amz_aws4_testsuite.data):
#             group = amz_aws4_testsuite.data[group_name]
#             # use new 3.4 subtests if available
#             if hasattr(self, "subTest"):
#                 with self.subTest(group_name=group_name, group=group):
#                     self._test_amz_test_suite_item(group_name, group)
#             else:
#                 self._test_amz_test_suite_item(group_name, group)
#
#     def _test_amz_test_suite_item(self, group_name, group):
#         req = request_from_text(group[".req"])
#         if "content-length" in req.headers:
#             del req.headers["content-length"]
#         include_hdrs = list(req.headers)
#         hsh = hashlib.sha256(req.content or b"")
#         req.headers["x-amz-content-sha256"] = hsh.hexdigest()
#         result = AWS4Auth.get_canonical_headers(req, include_hdrs)
#         cano_headers, signed_headers = result
#         auth = AWS4Auth("dummy", "dummy", "dummy", "host")
#         cano_req = auth.get_canonical_request(req, cano_headers, signed_headers)
#         msg = "Group: " + group_name
#         self.assertEqual(cano_req, group[".creq"], msg=msg)
#
#
# class AWS4Auth_RequestSign_Test(unittest.TestCase):
#     def test_generate_signature(self):
#         """
#         Using example data from
#         http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#         """
#         secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
#         region = "us-east-1"
#         service = "iam"
#         date = "20110909"
#         key = AWS4SigningKey(secret_key, region, service, date)
#         req_text = [
#             "POST https://iam.amazonaws.com/ HTTP/1.1",
#             "Host: iam.amazonaws.com",
#             "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
#             "User-Agent:python-httpx",
#             "X-Amz-Date: 20110909T233600Z",
#             "",
#             "Action=ListUsers&Version=2010-05-08",
#         ]
#         req_text = "\n".join(req_text) + "\n"
#         req = request_from_text(req_text)
#         del req.headers["content-length"]
#         include_hdrs = list(req.headers)
#         auth = AWS4Auth("dummy", key, include_hdrs=include_hdrs)
#         hsh = hashlib.sha256(req.content)
#         req.headers["x-amz-content-sha256"] = hsh.hexdigest()
#         sreq = next(auth.auth_flow(req))
#         signature = sreq.headers["Authorization"].split("=")[3]
#         expected = "d50ec75eed10aeb2cb3ddf6702d65d3bce310464d99da6f1af092bbc0f238295"
#         self.assertEqual(signature, expected)
#
#     def test_generate_empty_body_signature(self):
#         """
#         Check that change in af03ce5 doesn't regress - ensure request body is
#         not altered by signing process if it is empty (i.e None).
#         """
#         auth = AWS4Auth("x", "x", "us-east-1", "s3")
#         req = httpx.Request("GET", "http://amazonaws.com", data=None)
#         sreq = next(auth.auth_flow(req))
#         signature = sreq.headers["Authorization"].split("=")[3]
#         self.assertIsNotNone(signature)
#
#     def test_regen_key_on_date_mismatch(self):
#         vals = [
#             ("20001231T235959Z", "20010101"),
#             ("20000101T010101Z", "20000102"),
#             ("19900101T010101Z", "20000101"),
#         ]
#         for amzdate, scope_date in vals:
#             req = httpx.Request("GET", "http://blah.com")
#             if "date" in req.headers:
#                 del req.headers["date"]
#             req.headers["x-amz-date"] = amzdate
#             secret_key = "dummy"
#             region = "us-east-1"
#             service = "iam"
#             date = scope_date
#             key = AWS4SigningKey(secret_key, region, service, date)
#             orig_id = id(key)
#             auth = AWS4Auth("dummy", key)
#             sreq = next(auth.auth_flow(req))
#             self.assertNotEqual(id(auth.signing_key), orig_id)
#             self.assertEqual(auth.date, amzdate.split("T")[0])
#
#     @staticmethod
#     def check_auth(auth, req):
#         sreq = next(auth.auth_flow(req))
#
#     def test_raise_date_mismatch_error_on_date_mismatch(self):
#
#         amzdate, scope_date = ("20001231T235959Z", "20010101")
#         req = httpx.Request("GET", "http://blah.com")
#         if "date" in req.headers:
#             del req.headers["date"]
#         req.headers["x-amz-date"] = amzdate
#         secret_key = "dummy"
#         region = "us-east-1"
#         service = "iam"
#         date = scope_date
#         key = AWS4SigningKey(secret_key, region, service, date)
#         orig_id = id(key)
#         auth = StrictAWS4Auth("dummy", key)
#         self.assertRaises(DateMismatchError, self.check_auth, auth, req)
#
#     def test_date_mismatch_nosecretkey_raise(self):
#         key = AWS4SigningKey("secret_key", "region", "service", "1999010", False)
#         auth = AWS4Auth("access_id", key)
#         req = httpx.Request("GET", "http://blah.com")
#         if "date" in req.headers:
#             del req.headers["date"]
#         req.headers["x-amz-date"] = "20000101T010101Z"
#         self.assertRaises(NoSecretKeyError, self.check_auth, auth, req)
#
#     def test_sts_creds_include_security_token_header(self):
#         key = AWS4SigningKey("secret_key", "region", "service", "1999010")
#         auth = AWS4Auth("access_id", key, session_token="sessiontoken")
#         req = httpx.Request("GET", "http://blah.com")
#         sreq = next(auth.auth_flow(req))
#         self.assertIn("x-amz-security-token", sreq.headers)
#         self.assertEqual(sreq.headers.get("x-amz-security-token"), "sessiontoken")
#
#     @unittest.skipIf(
#         amz_aws4_testsuite is None,
#         "aws4_testsuite unavailable,"
#         " download it from http://docs.aws.amazon.com/general/la"
#         "test/gr/samples/aws4_testsuite.zip",
#     )
#     def test_amz_test_suite(self):
#         for group_name in sorted(amz_aws4_testsuite.data):
#             # use new 3.4 subtests if available
#             if hasattr(self, "subTest"):
#                 with self.subTest(group_name=group_name):
#                     self._test_amz_test_suite_item(group_name)
#             else:
#                 self._test_amz_test_suite_item(group_name)
#
#     def _test_amz_test_suite_item(self, group_name):
#         group = amz_aws4_testsuite.data[group_name]
#         req = request_from_text(group[".req"])
#         if "content-length" in req.headers:
#             del req.headers["content-length"]
#         include_hdrs = list(req.headers)
#         hsh = hashlib.sha256(req.content or b"")
#         req.headers["x-amz-content-sha256"] = hsh.hexdigest()
#         req.headers["x-amz-date"] = amz_aws4_testsuite.timestamp
#         key = AWS4SigningKey(
#             amz_aws4_testsuite.secret_key,
#             amz_aws4_testsuite.region,
#             amz_aws4_testsuite.service,
#             amz_aws4_testsuite.date,
#         )
#         auth = AWS4Auth(amz_aws4_testsuite.access_id, key, include_hdrs=include_hdrs)
#         sreq = auth(req)
#         auth_hdr = sreq.headers["Authorization"]
#         msg = "Group: " + group_name
#         self.assertEqual(auth_hdr, group[".authz"], msg=msg)
#
#
# @unittest.skipIf(
#     live_access_id is None or live_secret_key is None,
#     "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables not"
#     " set, skipping live service tests",
# )
# class AWS4Auth_LiveService_Test(unittest.TestCase):
#     """
#     Tests against live AWS services. To run these you need to provide your
#     AWS access ID and access key in the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
#     environment variables respectively.
#     The AWS Support API is currently untested as it requires a premium
#     subscription, though connection parameters are supplied below if you wish
#     to try it.
#     The following services do not work with AWS auth version 4 and are excluded
#     from the tests:
#         * Simple Email Service (SES)' - AWS auth v3 only
#         * Simple Workflow Service - AWS auth v3 only
#         * Import/Export - AWS auth v2 only
#         * SimpleDB - AWS auth V2 only
#         * DevPay - AWS auth v1 only
#         * Mechanical Turk - has own signing mechanism
#     """
#
#     services = {
#         #   "AppStream": "appstream2.us-east-1.amazonaws.com/applications",
#         "Auto-Scaling": "autoscaling.us-east-1.amazonaws.com/?Action=DescribeAutoScalingInstances&Version=2011-01-01",
#         # "CloudFormation": "cloudformation.us-east-1.amazonaws.com?Action=ListStacks&Version=2010-05-15&SignatureVersion=4",
#         "CloudFront": "cloudfront.amazonaws.com/2014-11-06/distribution?MaxItems=1",
#         #  "CloudHSM": {
#         #     "method": "POST",
#         #     "req": "cloudhsm.us-east-1.amazonaws.com",
#         #     "headers": {
#         #         "X-Amz-Target": "CloudHsmFrontendService.ListAvailableZones",
#         #         "Content-Type": "application/x-amz-json-1.1",
#         #     },
#         #     "body": "{}",
#         # },
#         # "CloudSearch": "cloudsearch.us-east-1.amazonaws.com?Action=ListDomainNames&Version=2013-01-01",
#         # "CloudTrail": "cloudtrail.us-east-1.amazonaws.com?Action=DescribeTrails",
#         # "CloudWatch (monitoring)": "monitoring.us-east-1.amazonaws.com?Action=ListMetrics",
#         # "CloudWatch (logs)": {
#         #    "method": "POST",
#         #    "req": "logs.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "X-Amz-Target": "Logs_20140328.DescribeLogGroups",
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #    },
#         #    "body": "{}",
#         # },
#         # "CodeDeploy": {
#         #    "method": "POST",
#         #    "req": "codedeploy.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "X-Amz-Target": "CodeDeploy_20141006.ListApplications",
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #    },
#         #    "body": "{}",
#         # },
#         "Cognito Identity": {
#             "method": "POST",
#             "req": "cognito-identity.us-east-1.amazonaws.com",
#             "headers": {
#                 "Content-Type": "application/json",
#                 "X-Amz_Target": "AWSCognitoIdentityService.ListIdentityPools",
#             },
#             "body": json.dumps(
#                 {
#                     "Operation": (
#                         "com.amazonaws.cognito.identity.model#ListIdentityPools"
#                     ),
#                     "Service": (
#                         "com.amazonaws.cognito.identity.model#AWSCognitoIdentityService"
#                     ),
#                     "Input": {"MaxResults": 1},
#                 }
#             ),
#         },
#         "Cognito Sync": {
#             "method": "POST",
#             "req": "cognito-sync.us-east-1.amazonaws.com",
#             "headers": {
#                 "Content-Type": "application/json",
#                 "X-Amz_Target": "AWSCognitoSyncService.ListIdentityPoolUsage",
#             },
#             "body": json.dumps(
#                 {
#                     "Operation": (
#                         "com.amazonaws.cognito.sync.model#ListIdentityPoolUsage"
#                     ),
#                     "Service": "com.amazonaws.cognito.sync.model#AWSCognitoSyncService",
#                     "Input": {"MaxResults": "1"},
#                 }
#             ),
#         },
#         # "Config": {
#         #    "method": "POST",
#         #    "req": "config.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "X-Amz-Target": "StarlingDoveService.DescribeDeliveryChannels",
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #    },
#         #    "body": "{}",
#         # },
#         # "DataPipeline": {
#         #    "req": "datapipeline.us-east-1.amazonaws.com?Action=ListPipelines",
#         #    "headers": {"X-Amz-Target": "DataPipeline.ListPipelines"},
#         #    "body": "{}",
#         # },
#         # "Direct Connect": {
#         #    "method": "POST",
#         #    "req": "directconnect.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "X-Amz-Target": "OvertureService.DescribeConnections",
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #    },
#         #    "body": "{}",
#         # },
#         # "DynamoDB": {
#         #    "method": "POST",
#         #    "req": "dynamodb.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "X-Amz-Target": "DynamoDB_20111205.ListTables",
#         #        "Content-Type": "application/x-amz-json-1.0",
#         #    },
#         #    "body": "{}",
#         # },
#         "Elastic Beanstalk": "elasticbeanstalk.us-east-1.amazonaws.com/?Action=ListAvailableSolutionStacks&Version=2010-12-01",
#         "ElastiCache": "elasticache.us-east-1.amazonaws.com/?Action=DescribeCacheClusters&Version=2014-07-15",
#         "EC2": "ec2.us-east-1.amazonaws.com/?Action=DescribeRegions&Version=2014-06-15",
#         "EC2 Container Service": (
#             "ecs.us-east-1.amazonaws.com/?Action=ListClusters&Version=2014-11-13"
#         ),
#         "Elastic Load Balancing": "elasticloadbalancing.us-east-1.amazonaws.com/?Action=DescribeLoadBalancers&Version=2012-06-01",
#         "Elastic MapReduce": "elasticmapreduce.us-east-1.amazonaws.com/?Action=ListClusters&Version=2009-03-31",
#         "Elastic Transcoder": (
#             "elastictranscoder.us-east-1.amazonaws.com/2012-09-25/pipelines"
#         ),
#         "Glacier": {
#             "req": "glacier.us-east-1.amazonaws.com/-/vaults",
#             "headers": {"X-Amz-Glacier-Version": "2012-06-01"},
#         },
#         "Identity and Access Management (IAM)": (
#             "iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
#         ),
#         # "Key Management Service": {
#         #    "method": "POST",
#         #    "req": "kms.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #        "X-Amz-Target": "TrentService.ListKeys",
#         #    },
#         #    "body": "{}",
#         # },
#         # "Kinesis": {
#         #     "method": "POST",
#         #     "req": "kinesis.us-east-1.amazonaws.com",
#         #     "headers": {
#         #         "Content-Type": "application/x-amz-json-1.1",
#         #         "X-Amz-Target": "Kinesis_20131202.ListStreams",
#         #     },
#         #     "body": "{}",
#         # },
#         "Lambda": "lambda.us-east-1.amazonaws.com/2014-11-13/functions/",
#         # "Opsworks": {
#         #    "method": "POST",
#         #    "req": "opsworks.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #        "X-Amz-Target": "OpsWorks_20130218.DescribeStacks",
#         #    },
#         #    "body": "{}",
#         # },
#         "Redshift": "redshift.us-east-1.amazonaws.com/?Action=DescribeClusters&Version=2012-12-01",
#         "Relational Database Service (RDS)": (
#             "rds.us-east-1.amazonaws.com/?Action=DescribeDBInstances&Version=2012-09-17"
#         ),
#         "Route 53": "route53.amazonaws.com/2013-04-01/hostedzone",
#         # "Simple Storage Service (S3)": "s3.amazonaws.com",
#         "Simple Notification Service (SNS)": (
#             "sns.us-east-1.amazonaws.com/?Action=ListTopics&Version=2010-03-31"
#         ),
#         "Simple Queue Service (SQS)": "sqs.us-east-1.amazonaws.com/?Action=ListQueues",
#         # "Storage Gateway": {
#         #    "method": "POST",
#         #    "req": "storagegateway.us-east-1.amazonaws.com",
#         #    "headers": {
#         #        "Content-Type": "application/x-amz-json-1.1",
#         #        "X-Amz-Target": "StorageGateway_20120630.ListGateways",
#         #    },
#         #    "body": "{}",
#         # },
#         "Security Token Service": (
#             "sts.amazonaws.com/?Action=GetSessionToken&Version=2011-06-15"
#         ),
#         # 'Support': {
#         #     'method': 'POST',
#         #     'req': 'support.us-east-1.amazonaws.com',
#         #     'headers': {'Content-Type': 'application/x-amz-json-1.0',
#         #                 'X-Amz-Target': 'Support_20130415.DescribeServices'},
#         #     'body': '{}'},
#     }
#
#     def test_live_services(self):
#         for service_name in sorted(self.services):
#             params = self.services[service_name]
#             # use new 3.4 subtests if available
#             if hasattr(self, "subTest"):
#                 with self.subTest(service_name=service_name, params=params):
#                     self._test_live_service(service_name, params)
#             else:
#                 self._test_live_service(service_name, params)
#
#     def _test_live_service(self, service_name, params):
#         if isinstance(params, dict):
#             method = params.get("method", "GET")
#             path_qs = params["req"]
#             headers = params.get("headers", {})
#             body = params.get("body", "")
#         else:
#             method = "GET"
#             path_qs = params
#             headers = {}
#             body = ""
#         service = path_qs.split(".")[0]
#         url = "https://" + path_qs
#         region = "us-east-1"
#         auth = AWS4Auth(live_access_id, live_secret_key, region, service)
#         response = httpx.request(method, url, auth=auth, data=body, headers=headers)
#         self.assertEqual(response.status_code, httpx.codes.OK)
#
#     def test_pinpoint(self):
#         url = "https://pinpoint.us-east-1.amazonaws.com/v1/apps"
#         service = "mobiletargeting"
#         region = "us-east-1"
#         dt = datetime.datetime.utcnow()
#         date = dt.strftime("%Y%m%d")
#         sig_key = AWS4SigningKey(live_secret_key, region, service, date)
#         auth = AWS4Auth(live_access_id, sig_key)
#         headers = {
#             "Content-Type": "application/json",
#             "X-Amz-Date": dt.strftime("%Y%m%dT%H%M%SZ"),
#         }
#         response = httpx.get(url, auth=auth, headers=headers)
#         self.assertEqual(response.status_code, httpx.codes.OK)


@pytest.fixture
def mock_aws_datetime(monkeypatch):
    _date_time_for_tests = datetime.datetime(2018, 10, 11, 15, 5, 5, 663979)

    class DateTimeModuleMock:
        class DateTimeMock:
            @staticmethod
            def utcnow():
                return _date_time_for_tests

        datetime = DateTimeMock

    import httpx_auth.aws

    monkeypatch.setattr(httpx_auth.aws, "datetime", DateTimeModuleMock)


def test_aws_auth_with_empty_secret_key(httpx_mock: HTTPXMock, mock_aws_datetime):
    with pytest.raises(Exception) as exception_info:
        httpx_auth.AWS4Auth(
            access_id="access_id", secret_key="", region="us-east-1", service="iam"
        )
    assert str(exception_info.value) == "Secret key is mandatory."


def test_aws_auth_without_content_in_request(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=b26b1ba261652e67fee5174c7fa1de1ef8f74e9d8e427528e197ce5e64d52d74"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_with_content_in_request(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", json=[{"key": "value"}], auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "fb65c1441d6743274738fe3b3042a73167ba1fb2d34679d8dd16433473758f97"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, "
        "Signature=a70f3cf3c14bd0e2cc048dfb7ddf63f9b2c12615476ebcb75f224f7a0192e383"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_with_security_token_and_without_content_in_request(
    httpx_mock: HTTPXMock, mock_aws_datetime
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, "
        "Signature=be2b7efe21f69856b1dae871064627909cc1cac0749f3237dee0df99123e21a3"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"
    assert headers["x-amz-security-token"] == "security_token"


def test_aws_auth_with_security_token_and_content_in_request(
    httpx_mock: HTTPXMock, mock_aws_datetime
):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
        security_token="security_token",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only", json=[{"key": "value"}], auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "fb65c1441d6743274738fe3b3042a73167ba1fb2d34679d8dd16433473758f97"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, "
        "Signature=ff98a199b570988a5d2891939a1a4a5e98e4171329a53c7306fc7a19ef6cad23"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"
    assert headers["x-amz-security-token"] == "security_token"


def test_aws_auth_override_x_amz_date_header(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post(
        "http://authorized_only", headers={"x-amz-date": "20201011T150505Z"}, auth=auth
    )
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=b26b1ba261652e67fee5174c7fa1de1ef8f74e9d8e427528e197ce5e64d52d74"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_root_path(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only")

    httpx.post("http://authorized_only/", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=ce708380ee69b1a9558b9b0dddd4d15f35a2a5e5ea3534b541247f1a746626db"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_query_parameters(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only?param1&param2=blah*")

    httpx.post("http://authorized_only?param1&param2=blah*", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=959173877981331c60d6b4cf45795a922f6639ec9714837ebb5ff009ae129fde"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_normalize(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(url="http://authorized_only/stuff//more/")

    httpx.post("http://authorized_only/./test/../stuff//more/", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=e49fb885d30c9e74901071748b783fabe8ba7a979aa20420ac76af1dda1edd03"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_quoting(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(
        url="http://authorized_only/test/hello-*.&%5E%7E+%7B%7D!$%C2%A3_%20"
    )

    httpx.post("http://authorized_only/test/hello-*.&^~+{}!$£_ ", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=98dd3cdd2a603907495164f08fe7197fb405bf8c556ddf7b88d7e15341a9588a"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_percent_encode_non_s3(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="iam",
    )
    httpx_mock.add_response(
        url="http://authorized_only/test/%252a%252b%2525/%7E-_%5E&%20%25%25"
    )

    httpx.post("http://authorized_only/test/%2a%2b%25/~-_^& %%", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/iam/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=1da6c689b7a20044144a9f265ddecc38b1b884902846fbe4dc8049595f25565f"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"


def test_aws_auth_path_percent_encode_s3(httpx_mock: HTTPXMock, mock_aws_datetime):
    auth = httpx_auth.AWS4Auth(
        access_id="access_id",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="s3",
    )
    httpx_mock.add_response(
        url="http://authorized_only/test/%252a%252b%2525/%7E-_%5E&%20%25%25"
    )

    httpx.post("http://authorized_only/test/%2a%2b%25/~-_^& %%", auth=auth)
    headers = httpx_mock.get_request().headers
    assert (
        headers["x-amz-content-sha256"]
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert (
        headers["Authorization"] == "AWS4-HMAC-SHA256 "
        "Credential=access_id/20181011/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
        "Signature=2fc7c2f27151e18348862bab0bbe90c4a9f29d7863a33e725d7b1ec96709fdd6"
    )
    assert headers["x-amz-date"] == "20181011T150505Z"

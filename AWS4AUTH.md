httpx-auth.AWS4Auth class
=================

Amazon Web Services version 4 authentication for the Python [`httpx`](https://github.com/encode/httpx) library.

AWS4Auth is based on [request-aws4auth](https://github.com/sam-washington/requests-aws4auth) and should closely match its calling conventions and behavior

Features
--------
* Authentication for all AWS services that support AWS auth v4
* Independent signing key objects
* Automatic regeneration of keys when scope date boundary is passed 
* Support for STS temporary credentials

Implements header-based authentication, GET URL parameter and POST parameter
authentication are not supported.

Supported Services
------------------
This package has been tested as working against:

Auto-Scaling, CloudFormation, CloudFront, CloudSaerch, CloudTrail, 
CloudWatch (monitoring), CloudWatch (logs), CodeDeploy, Cognito Identity, 
Cognito Sync, Config, DataPipeline, Direct Connect, DynamoDB, Elastic Beanstalk, 
ElastiCache, EC2, EC2 Container Service, Elastic Load Balancing,
Elastic MapReduce, ElasticSearch, Elastic Transcoder, Glacier, 
Identity and Access Management (IAM), Key Management Service (KMS), Kinesis, 
Lambda, Opsworks, Redshift, Relational Database Service (RDS), Route 53,
Simple Storage Service (S3), Simple Notification Service (SNS), 
Simple Queue Service (SQS), Storage Gateway, Security Token Service (STS), Pinpoint

the AWS4Auth class has been tested on python 3.6, 3.7 and 3.8

Basic usage
-----------

    import httpx
    from httpx_auth import AWS4Auth
    endpoint = 'http://s3-eu-west-1.amazonaws.com'
    auth = AWS4Auth('<ACCESS ID>', '<ACCESS KEY>', 'eu-west-1', 's3')
    response = httpx.get(endpoint, auth=auth)
    print(response.text)
    <?xml version="1.0" encoding="UTF-8"?>
        <ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01">
            <Owner>
            <ID>bcaf1ffd86f461ca5fb16fd081034f</ID>
            <DisplayName>webfile</DisplayName>
            ...

This example would list your buckets in the ``eu-west-1`` region of the Amazon
S3 service.

STS Temporary Credentials
-------------------------

    from httpx_auth import AWS4Auth
    auth = AWS4Auth('<ACCESS ID>', '<ACCESS KEY>', 'eu-west-1', 's3',
                        session_token='<SESSION TOKEN>')
    ...

This example shows how to construct an AWS4Auth object for use with STS
temporary credentials. The ``x-amz-security-token`` header is added with
the session token. Temporary credential timeouts are not managed -- in
case the temporary credentials expire, they need to be re-generated and
the AWS4Auth object re-constructed with the new credentials.

Date handling
-------------
If an HTTP request to be authenticated contains a ``Date`` or ``X-Amz-Date``
header, AWS will only accept the authorised request if the date in the header
matches the scope date of the signing key see the [AWS REST API date docs](http://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html).

If the header date does not match the scope date, an ``AWS4Auth`` instance will 
automatically regenerate its signing key, using the same scope parameters as the 
previous key except for the date, which will be changed to match the request date. 
If a request does not include a date, the current date is added to the request in 
an ``X-Amz-Date`` header, and the signing key is regenerated if this differs from 
the scope date.

This means that ``AWS4Auth`` now extracts and parses dates from the values of
``X-Amz-Date`` and ``Date`` headers. Supported date formats are:

* RFC 7231 (e.g. Mon, 09 Sep 2011 23:36:00 GMT)
* RFC 850 (e.g. Sunday, 06-Nov-94 08:49:37 GMT)
* C time (e.g. Wed Dec 4 00:00:00 2002)
* Amz-Date format (e.g. 20090325T010101Z)
* ISO 8601 / RFC 3339 (e.g. 2009-03-25T10:11:12.13-01:00)

If either header is present but ``AWS4Auth`` cannot extract a date because all
present date headers are in an unrecognisable format, ``AWS4Auth`` will delete
any ``X-Amz-Date`` and ``Date`` headers present and replace with a single
``X-Amz-Date`` header containing the current date. This behaviour can be
modified using the ``raise_invalid_date`` keyword argument of the ``AWS4Auth``
constructor.

Automatic key regeneration
--------------------------
If you do not want the signing key to be automatically regenerated when a
mismatch between the request date and the scope date is encountered, use the
alternative ``StrictAWS4Auth`` class, which is identical to ``AWS4Auth`` except
that upon encountering a date mismatch it just raises a ``DateMismatchError``.

Secret key storage
------------------
To allow automatic key regeneration, the secret key is stored in the
``AWS4Auth`` instance, in the signing key object. If you do not want this to
occur, instantiate the instance using an ``AWS4Signing`` key which was created
with the store_secret_key parameter set to False:

    sig_key = AWS4SigningKey(secret_key, region, service, date, False)
    auth = StrictAWS4Auth(access_id, sig_key)

The ``AWS4Auth`` class will then raise a ``NoSecretKeyError`` when it attempts
to regenerate its key. A slightly more conceptually elegant way to handle this
is to use the alternative ``StrictAWS4Auth`` class, again instantiating it with
an ``AWS4SigningKey`` instance created with ``store_secret_key = False``.

Multithreading
--------------
If you share ``AWS4Auth`` (or even ``StrictAWS4Auth``) instances between
threads you are likely to encounter problems. Because ``AWS4Auth`` instances
may unpredictably regenerate their signing key as part of signing a request,
threads using the same instance may find the key changed by another thread
halfway through the signing process, which may result in undefined behaviour.

In short, it's probably best to create a thread-local instance of ``AWS4Auth``
for each thread that needs to do authentication.

API reference
-------------
See the doctrings in ``aws4auth.py``.

Testing
-------
A test suite is included in the tests/test_aws4auth.py file. 


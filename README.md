<h2 align="center">Authentication for HTTPX</h2>

<p align="center">
<a href="https://pypi.org/project/httpx-auth/"><img alt="pypi version" src="https://img.shields.io/pypi/v/httpx_auth"></a>
<a href="https://github.com/Colin-b/httpx_auth/actions"><img alt="Build status" src="https://github.com/Colin-b/httpx_auth/workflows/Release/badge.svg"></a>
<a href="https://github.com/Colin-b/httpx_auth/actions"><img alt="Coverage" src="https://img.shields.io/badge/coverage-100%25-brightgreen"></a>
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
<a href="https://github.com/Colin-b/httpx_auth/actions"><img alt="Number of tests" src="https://img.shields.io/badge/tests-783 passed-blue"></a>
<a href="https://pypi.org/project/httpx-auth/"><img alt="Number of downloads" src="https://img.shields.io/pypi/dm/httpx_auth"></a>
</p>

> [!NOTE]  
> Version 1.0.0 will be released once httpx is considered as stable (release of 1.0.0).
>
> However, current state can be considered as stable.

Provides authentication classes to be used with [`httpx`][1] [authentication parameter][2].

<p align="center">
    <a href="https://oauth.net/2/"><img alt="OAuth2" src="https://oauth.net/images/oauth-2-sm.png"></a>
    <a href="https://www.okta.com"><img alt="Okta" src="https://www.okta.com/sites/all/themes/Okta/images/logos/developer/Dev_Logo-03_Large.png" height="120"></a>
    <a href="https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id"><img alt="Microsoft Entra ID, formerly Azure Active Directory (AD)" src="https://svgshare.com/i/12u_.svg" height="120"></a>
    <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html"><img alt="AWS Signature Version 4" src="https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg" height="120"></a>
</p>
<p align="center">Some of the supported authentication</p>

## Available authentication

- [OAuth2](#oauth-2)
  - [Authorization Code Flow](#authorization-code-flow)
    - [Okta](#okta-oauth2-authorization-code)
    - [WakaTime](#wakatime-oauth2-authorization-code)
  - [Authorization Code Flow with PKCE](#authorization-code-flow-with-proof-key-for-code-exchange)
    - [Okta](#okta-oauth2-proof-key-for-code-exchange)
  - [Resource Owner Password Credentials flow](#resource-owner-password-credentials-flow)
  - [Client Credentials Flow](#client-credentials-flow)
    - [Okta](#okta-oauth2-client-credentials)
  - [Implicit Flow](#implicit-flow)
    - [Microsoft Entra (Access Token)](#microsoft---azure-active-directory-oauth2-access-token)
    - [Microsoft Entra (ID token)](#microsoft---azure-active-directory-openid-connect-id-token)
    - [Okta (Access Token)](#okta-oauth2-implicit-access-token)
    - [Okta (ID token)](#okta-openid-connect-implicit-id-token)
  - [Managing token cache](#managing-token-cache)
  - [Managing browser](#managing-the-web-browser)
- [Amazon](#aws-signature-v4)
- API key
  - [In header](#api-key-in-header)
  - [In query](#api-key-in-query)
- [Basic](#basic)
- [Multiple authentication at once](#multiple-authentication-at-once)

## OAuth 2

Most of [OAuth2](https://oauth.net/2/) flows are supported.

If the one you are looking for is not yet supported, feel free to [ask for its implementation](https://github.com/Colin-b/httpx_auth/issues/new).

### Authorization Code flow

Authorization Code Grant is implemented following [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.1).

Use `httpx_auth.OAuth2AuthorizationCode` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OAuth2AuthorizationCode

with httpx.Client() as client:
    client.get('https://www.example.com', auth=OAuth2AuthorizationCode('https://www.authorization.url', 'https://www.token.url'))
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

#### Parameters

| Name                    | Description                                                                                                                                                                                                                                                                                       | Mandatory  | Default value  |
|:------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------|:---------------|
| `authorization_url`     | OAuth 2 authorization URL.                                                                                                                                                                                                                                                                        | Mandatory  |                |
| `token_url`             | OAuth 2 token URL.                                                                                                                                                                                                                                                                                | Mandatory  |                |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 code will be started.                                                                                                                                                                                                                      | Optional   | 5000           |
| `timeout`               | Maximum amount of seconds to wait for a code or a token to be received once requested.                                                                                                                                                                                                            | Optional   | 60             |
| `header_name`           | Name of the header field used to send token.                                                                                                                                                                                                                                                      | Optional   | Authorization  |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token.                                                                                                                                                                                        | Optional   | Bearer {token} |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL.                                                                                                                                                                                                          | Optional   | code           |
| `token_field_name`      | Field name containing the token.                                                                                                                                                                                                                                                                  | Optional   | access_token   |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional   | 30.0           |
| `code_field_name`       | Field name containing the code.                                                                                                                                                                                                                                                                   | Optional   | code           |
| `username`              | User name in case basic authentication should be used to retrieve token.                                                                                                                                                                                                                          | Optional   |                |
| `password`              | User password in case basic authentication should be used to retrieve token.                                                                                                                                                                                                                      | Optional   |                |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance.                                                                                                                                                                            | Optional   |                |

Any other parameter will be put as query parameter in the authorization URL and as body parameters in the token URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_id`     | Corresponding to your Application ID (in Microsoft Azure app portal) |
| `client_secret` | If client is not authenticated with the authorization server         |
| `nonce`         | Refer to [OpenID ID Token specifications][3] for more details        |

#### Common providers

Most of [OAuth2](https://oauth.net/2/) Authorization Code Grant providers are supported.

If the one you are looking for is not yet supported, feel free to [ask for its implementation](https://github.com/Colin-b/httpx_auth/issues/new).

##### Okta (OAuth2 Authorization Code)

[Okta Authorization Code Grant](https://developer.okta.com/docs/guides/implement-auth-code/overview/) providing access tokens is supported.

Use `httpx_auth.OktaAuthorizationCode` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OktaAuthorizationCode


okta = OktaAuthorizationCode(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=okta)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | Okta instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Okta Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional | Newly generated Universal Unique Identifier. |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | openid |
| `authorization_server`  | Okta authorization server. | Optional | 'default' |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional |  |

Any other parameter will be put as query parameter in the authorization URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### WakaTime (OAuth2 Authorization Code)

[WakaTime Authorization Code Grant](https://wakatime.com/developers#authentication) providing access tokens is supported.

Use `httpx_auth.WakaTimeAuthorizationCode` to configure this kind of authentication.

```python
import httpx
from httpx_auth import WakaTimeAuthorizationCode


waka_time = WakaTimeAuthorizationCode(client_id="aPJQV0op6Pu3b66MWDi9b1wB", client_secret="waka_sec_0c5MB", scope="email")
with httpx.Client() as client:
    client.get('https://wakatime.com/api/v1/users/current', auth=waka_time)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

###### Parameters

| Name                    | Description                | Mandatory | Default value                                |
|:------------------------|:---------------------------|:----------|:---------------------------------------------|
| `client_id`             | WakaTime Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |                                              |
| `client_secret`         | WakaTime Application Secret (formatted as waka_sec_ followed by an Universal Unique Identifier). | Mandatory |                                              |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Mandatory |                                              |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional  | token                                        |
| `token_field_name`      | Field name containing the token. | Optional  | access_token                                 |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0                                         |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional  | Newly generated Universal Unique Identifier. |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional  | 5000                                         |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional  | 60                                           |
| `header_name`           | Name of the header field used to send token. | Optional  | Authorization                                |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional  | Bearer {token}                               |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional  |                                              |

Any other parameter will be put as query parameter in the authorization URL.

### Authorization Code Flow with Proof Key for Code Exchange

Proof Key for Code Exchange is implemented following [rfc7636](https://tools.ietf.org/html/rfc7636).

Use `httpx_auth.OAuth2AuthorizationCodePKCE` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OAuth2AuthorizationCodePKCE

with httpx.Client() as client:
    client.get('https://www.example.com', auth=OAuth2AuthorizationCodePKCE('https://www.authorization.url', 'https://www.token.url'))
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

#### Parameters 

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `authorization_url`     | OAuth 2 authorization URL. | Mandatory |               |
| `token_url`             | OAuth 2 token URL.         | Mandatory |               |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 code will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a code or a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | code |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `code_field_name`       | Field name containing the code. | Optional | code |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional |  |

Any other parameter will be put as query parameter in the authorization URL and as body parameters in the token URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_id`     | Corresponding to your Application ID (in Microsoft Azure app portal) |
| `client_secret` | If client is not authenticated with the authorization server         |
| `nonce`         | Refer to [OpenID ID Token specifications][3] for more details        |

#### Common providers

Most of [OAuth2](https://oauth.net/2/) Proof Key for Code Exchange providers are supported.

If the one you are looking for is not yet supported, feel free to [ask for its implementation](https://github.com/Colin-b/httpx_auth/issues/new).

##### Okta (OAuth2 Proof Key for Code Exchange)

[Okta Proof Key for Code Exchange](https://developer.okta.com/docs/guides/implement-auth-code-pkce/overview/) providing access tokens is supported.

Use `httpx_auth.OktaAuthorizationCodePKCE` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OktaAuthorizationCodePKCE


okta = OktaAuthorizationCodePKCE(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=okta)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | Okta instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Okta Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | code |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `code_field_name`      | Field name containing the code. | Optional | code |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional | Newly generated Universal Unique Identifier. |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | openid |
| `authorization_server`  | Okta authorization server. | Optional | 'default' |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional |  |

Any other parameter will be put as query parameter in the authorization URL and as body parameters in the token URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_secret`        | If client is not authenticated with the authorization server     |
| `nonce`        | Refer to [OpenID ID Token specifications][3] for more details     |

### Resource Owner Password Credentials flow

Resource Owner Password Credentials Grant is implemented following [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.3).

Use `httpx_auth.OAuth2ResourceOwnerPasswordCredentials` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OAuth2ResourceOwnerPasswordCredentials

with httpx.Client() as client:
    client.get('https://www.example.com', auth=OAuth2ResourceOwnerPasswordCredentials('https://www.token.url', 'user name', 'user password'))
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).

#### Parameters

| Name                 | Description                                                                                                                                                                                                                                                                                       | Mandatory | Default value |
|:---------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------|:--------------|
| `token_url`          | OAuth 2 token URL.                                                                                                                                                                                                                                                                                | Mandatory |               |
| `username`           | Resource owner user name.                                                                                                                                                                                                                                                                         | Mandatory |               |
| `password`           | Resource owner password.                                                                                                                                                                                                                                                                          | Mandatory |               |
| `client_auth`        | Client authentication if the client type is confidential or the client was issued client credentials (or assigned other authentication requirements). Can be a tuple or any httpx authentication class instance.                                                                                  | Optional  |               |
| `timeout`            | Maximum amount of seconds to wait for a token to be received once requested.                                                                                                                                                                                                                      | Optional  | 60            |
| `header_name`        | Name of the header field used to send token.                                                                                                                                                                                                                                                      | Optional  | Authorization |
| `header_value`       | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token.                                                                                                                                                                                        | Optional  | Bearer {token} |
| `scope`              | Scope parameter sent to token URL as body. Can also be a list of scopes.                                                                                                                                                                                                                          | Optional  |  |
| `token_field_name`   | Field name containing the token.                                                                                                                                                                                                                                                                  | Optional  | access_token  |
| `early_expiry`       | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `client`             | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance.                                                                                                                                                                            | Optional  |  |

Any other parameter will be put as body parameter in the token URL.

#### Common providers

Most of [OAuth2](https://oauth.net/2/) Resource Owner Password Credentials providers are supported.

If the one you are looking for is not yet supported, feel free to [ask for its implementation](https://github.com/Colin-b/httpx_auth/issues/new).

##### Okta (OAuth2 Resource Owner Password Credentials)

[Okta Resource Owner Password Credentials](https://developer.okta.com/docs/guides/implement-grant-type/ropassword/main/) providing access tokens is supported.

Use `httpx_auth.OktaResourceOwnerPasswordCredentials` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OktaResourceOwnerPasswordCredentials


okta = OktaResourceOwnerPasswordCredentials(instance='testserver.okta-emea.com', username='user name', password='user password', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_secret="0c5MB")
with httpx.Client() as client:
    client.get('https://www.example.com', auth=okta)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | Okta instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `username`           | Resource owner user name.                                                                                                                                                                                                                                                                         | Mandatory |               |
| `password`           | Resource owner password.                                                                                                                                                                                                                                                                          | Mandatory |               |
| `client_id`             | Okta Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `client_secret`        | Resource owner password.     | Mandatory |               |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | openid |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional |  |

Any other parameter will be put as body parameters in the token URL.


### Client Credentials flow

Client Credentials Grant is implemented following [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.4).

Use `httpx_auth.OAuth2ClientCredentials` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OAuth2ClientCredentials

with httpx.Client() as client:
    client.get('https://www.example.com', auth=OAuth2ClientCredentials('https://www.token.url', client_id='id', client_secret='secret'))
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).

#### Parameters

| Name               | Description                                  | Mandatory | Default value |
|:-------------------|:---------------------------------------------|:----------|:--------------|
| `token_url`        | OAuth 2 token URL.                           | Mandatory |               |
| `client_id`         | Resource owner user name.                    | Mandatory |               |
| `client_secret`         | Resource owner password.                     | Mandatory |               |
| `timeout`          | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60            |
| `header_name`      | Name of the header field used to send token. | Optional  | Authorization |
| `header_value`     | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |
| `scope`            | Scope parameter sent to token URL as body. Can also be a list of scopes. | Optional |  |
| `token_field_name` | Field name containing the token.             | Optional  | access_token  |
| `early_expiry`     | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `client`           | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional |  |

Any other parameter will be put as body parameter in the token URL.

#### Common providers

Most of [OAuth2](https://oauth.net/2/) Client Credentials Grant providers are supported.

If the one you are looking for is not yet supported, feel free to [ask for its implementation](https://github.com/Colin-b/httpx_auth/issues/new).

##### Okta (OAuth2 Client Credentials)

[Okta Client Credentials Grant](https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/) providing access tokens is supported.

Use `httpx_auth.OktaClientCredentials` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OktaClientCredentials


okta = OktaClientCredentials(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_secret="secret", scope=["scope1", "scope2"])
with httpx.Client() as client:
    client.get('https://www.example.com', auth=okta)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | Okta instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Okta Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `client_secret`         | Resource owner password.                     | Mandatory |               |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Mandatory |  |
| `authorization_server`  | Okta authorization server. | Optional  | 'default' |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional  | 60 |
| `header_name`           | Name of the header field used to send token. | Optional  | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional  | Bearer {token} |
| `token_field_name`      | Field name containing the token. | Optional  | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `client`                | `httpx.Client` instance that will be used to request the token. Use it to provide a custom proxying rule for instance. | Optional  |  |

Any other parameter will be put as query parameter in the token URL.        

### Implicit flow

Implicit Grant is implemented following [rfc6749](https://tools.ietf.org/html/rfc6749#section-4.2).

Use `httpx_auth.OAuth2Implicit` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OAuth2Implicit

with httpx.Client() as client:
    client.get('https://www.example.com', auth=OAuth2Implicit('https://www.authorization.url'))
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

#### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `authorization_url`     | OAuth 2 authorization URL. | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | id_token if response_type is id_token, otherwise access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `client_id`     | Corresponding to your Application ID (in Microsoft Azure app portal) |
| `nonce`         | Refer to [OpenID ID Token specifications][3] for more details        |
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

#### Common providers

Most of [OAuth2](https://oauth.net/2/) Implicit Grant providers are supported.

If the one you are looking for is not yet supported, feel free to [ask for its implementation](https://github.com/Colin-b/httpx_auth/issues/new).

##### Microsoft - Azure Active Directory (OAuth2 Access Token)

[Microsoft identity platform access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens) are supported.

Use `httpx_auth.AzureActiveDirectoryImplicit` to configure this kind of authentication.

```python
import httpx
from httpx_auth import AzureActiveDirectoryImplicit


aad = AzureActiveDirectoryImplicit(tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=aad)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

You can retrieve Microsoft Azure Active Directory application information thanks to the [application list on Azure portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AllApps/menuId/).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `tenant_id`             | Microsoft Tenant Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `client_id`             | Microsoft Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details | Optional | Newly generated Universal Unique Identifier. |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### Microsoft - Azure Active Directory (OpenID Connect ID token)

[Microsoft identity platform ID tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens) are supported.

Use `httpx_auth.AzureActiveDirectoryImplicitIdToken` to configure this kind of authentication.

```python
import httpx
from httpx_auth import AzureActiveDirectoryImplicitIdToken


aad = AzureActiveDirectoryImplicitIdToken(tenant_id='45239d18-c68c-4c47-8bdd-ce71ea1d50cd', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=aad)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

You can retrieve Microsoft Azure Active Directory application information thanks to the [application list on Azure portal](https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AllApps/menuId/).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `tenant_id`             | Microsoft Tenant Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `client_id`             | Microsoft Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | id_token |
| `token_field_name`      | Field name containing the token. | Optional | id_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details | Optional | Newly generated Universal Unique Identifier. |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### Okta (OAuth2 Implicit Access Token)

[Okta Implicit Grant](https://developer.okta.com/docs/guides/implement-implicit/overview/) providing access tokens is supported.

Use `httpx_auth.OktaImplicit` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OktaImplicit


okta = OktaImplicit(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=okta)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | Okta instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Okta Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | token |
| `token_field_name`      | Field name containing the token. | Optional | access_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional | Newly generated Universal Unique Identifier. |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | ['openid', 'profile', 'email'] |
| `authorization_server`  | Okta authorization server. | Optional | 'default' |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

##### Okta (OpenID Connect Implicit ID token)

[Okta Implicit Grant](https://developer.okta.com/docs/guides/implement-implicit/overview/) providing ID tokens is supported.

Use `httpx_auth.OktaImplicitIdToken` to configure this kind of authentication.

```python
import httpx
from httpx_auth import OktaImplicitIdToken


okta = OktaImplicitIdToken(instance='testserver.okta-emea.com', client_id='54239d18-c68c-4c47-8bdd-ce71ea1d50cd')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=okta)
```

Note:
* You can persist tokens thanks to [the token cache](#managing-token-cache).
* You can tweak web browser interaction thanks to [the display settings](#managing-the-web-browser).

###### Parameters

| Name                    | Description                | Mandatory | Default value |
|:------------------------|:---------------------------|:----------|:--------------|
| `instance`              | Okta instance (like "testserver.okta-emea.com"). | Mandatory |               |
| `client_id`             | Okta Application Identifier (formatted as an Universal Unique Identifier). | Mandatory |               |
| `response_type`         | Value of the response_type query parameter if not already provided in authorization URL. | Optional | id_token |
| `token_field_name`      | Field name containing the token. | Optional | id_token |
| `early_expiry`          | Number of seconds before actual token expiry where token will be considered as expired. Used to ensure token will not expire between the time of retrieval and the time the request reaches the actual server. Set it to 0 to deactivate this feature and use the same token until actual expiry. | Optional  | 30.0  |
| `nonce`                 | Refer to [OpenID ID Token specifications][3] for more details. | Optional | Newly generated Universal Unique Identifier. |
| `scope`                 | Scope parameter sent in query. Can also be a list of scopes. | Optional | ['openid', 'profile', 'email'] |
| `authorization_server`  | Okta authorization server. | Optional | 'default' |
| `redirect_uri_domain`   | [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to use in the redirect_uri when localhost is not allowed.                                                                                                                                                                       | Optional   | localhost      |
| `redirect_uri_endpoint` | Custom endpoint that will be used as redirect_uri the following way: http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>.                                                                                                                                                    | Optional   | ''             |
| `redirect_uri_port`     | The port on which the server listening for the OAuth 2 token will be started. | Optional | 5000 |
| `timeout`               | Maximum amount of seconds to wait for a token to be received once requested. | Optional | 60 |
| `header_name`           | Name of the header field used to send token. | Optional | Authorization |
| `header_value`          | Format used to send the token value. "{token}" must be present as it will be replaced by the actual token. | Optional | Bearer {token} |

Any other parameter will be put as query parameter in the authorization URL.        

Usual extra parameters are:
        
| Name            | Description                                                          |
|:----------------|:---------------------------------------------------------------------|
| `prompt`        | none to avoid prompting the user if a session is already opened.     |

### Managing token cache

To avoid asking for a new token every new request, a token cache is used.

Default cache is in memory, but it is also possible to use a physical cache.

You need to provide the location of your token cache file. It can be a full or relative path (`str` or `pathlib.Path`).

If the file already exists it will be used, if the file do not exist it will be created.

```python
from httpx_auth import OAuth2, JsonTokenFileCache

OAuth2.token_cache = JsonTokenFileCache('path/to/my_token_cache.json')
```

### Managing the web browser

#### Authentication response pages

You can configure the browser display settings thanks to `httpx_auth.OAuth2.display` as in the following:
```python
from httpx_auth import OAuth2, DisplaySettings

OAuth2.display = DisplaySettings()
```

The following parameters can be provided to `DisplaySettings`:

| Name                   | Description                                                                                                                                                                      | Default value |
|:-----------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------|
| `success_display_time` | In case a code or token is successfully received, this is the maximum amount of milliseconds the success page will be displayed in your browser.                                 | 1             |
| `success_html`         | In case a code or token is successfully received, this is the success page that will be displayed in your browser. `{display_time}` is expected in this content.                 |               |
| `failure_display_time` | In case received code or token is not valid, this is the maximum amount of milliseconds the failure page will be displayed in your browser.                                      | 10_000        |
| `failure_html`         | In case received code or token is not valid, this is the failure page that will be displayed in your browser. `{information}` and `{display_time}` are expected in this content. |               |

#### Text-mode web browser

This project uses [`webbrowser.open()`][4] to open a web browser to support authentication flows like OAuth's Authorization Code grant. When running graphically, `webbrowser.open()` does not block. But when run in text mode, `webbrowser.open()` blocks until the opened browser is closed, which leads to a deadlock when httpx-auth cannot serve the auth response pages to the webbrowser. To work around this, you can specify a `BROWSER` environment variable that contains a `%s` and ends with a `&`, and the `webbrowser` module will open the text-mode browser in a subprocess and allow httpx-auth to serve the auth response pages to the browser without deadlocking.

```bash
BROWSER="/usr/bin/links %s &"
```

For more information, please see the implementation of [`webbrowser.get()`][5].

## AWS Signature v4

Amazon Web Service Signature version 4 is implemented following [Amazon S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html) and [request-aws4auth 1.2.3](https://github.com/sam-washington/requests-aws4auth) (with some changes, see below).

Use `httpx_auth.AWS4Auth` to configure this kind of authentication.

```python
import httpx
from httpx_auth import AWS4Auth

aws = AWS4Auth(access_id="my-access-id", secret_key="my-secret-key", region="eu-west-1", service="s3")
with httpx.Client() as client:
    client.get('http://s3-eu-west-1.amazonaws.com', auth=aws)
```

Note that the following changes were made compared to `requests-aws4auth`:
  - Each request now has its own signing key and `x-amz-date`. Meaning **you can use the same auth instance for more than one request**.
  - `session_token` was renamed into `security_token` for consistency with the underlying name at Amazon.
  - `include_hdrs` parameter was renamed into `include_headers`. When using this parameter:
    - Provided values will not be stripped, [WYSIWYG](https://en.wikipedia.org/wiki/WYSIWYG).
    - If multiple values are provided for a same header, the computation will be based on the value order you provided and value separated by `, `. Instead of ordered values separated by comma for `requests-aws4auth`.
  - `amz_date` attribute has been removed.
  - It is not possible to provide a `date`. It will default to now.
  - It is not possible to provide an `AWSSigningKey` instance, use explicit parameters instead.
  - It is not possible to provide `raise_invalid_date` parameter anymore as the date will always be valid.
  - `host` is not considered as a specific Amazon service anymore (no test specific code).
  - Canonical query string computation is entirely based on AWS documentation (and consider undocumented fragment (`#` and following characters) as part of the query string).
  - Canonical uri computation is entirely based on AWS documentation.
  - Canonical headers computation is entirely based on AWS documentation.

### Parameters

| Name               | Description                                                                                                                                                                                    | Mandatory  | Default value                                                                                                            |
|:-------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------|:-------------------------------------------------------------------------------------------------------------------------|
| `access_id`        | AWS access ID.                                                                                                                                                                                 | Mandatory  |                                                                                                                          |
| `secret_key`       | AWS secret access key.                                                                                                                                                                         | Mandatory  |                                                                                                                          |
| `region`           | The region you are connecting to, as per [this list](http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region). For services which do not require a region (e.g. IAM), use us-east-1. | Mandatory  |                                                                                                                          |
| `service`          | The name of the service you are connecting to, as per [this list](http://docs.aws.amazon.com/general/latest/gr/rande.html). e.g. elasticbeanstalk.                                             | Mandatory  |                                                                                                                          |
| `security_token`   | Used for the `x-amz-security-token` header, for use with STS temporary credentials.                                                                                                            | Optional   |                                                                                                                          |
| `include_headers`  | Set of headers to include in the canonical and signed headers (in addition to the default). Note that `x-amz-client-context` is not included by default and `*` will include all headers.      | Optional   | {"host", "content-type", "x-amz-*"} and if `security_token` is provided, `x-amz-security-token`. |

### Dynamically retrieving credentials using boto3

While `httpx-auth` does not want to include support for `botocore`, the following authentication class should allow you to automatically retrieve up-to-date credentials.

```python
import httpx
from botocore.session import Session
from httpx_auth import AWS4Auth

class AWS4BotoAuth(AWS4Auth):
    def __init__(self, region: str, service: str = "s3", **kwargs):
        self.refreshable_credentials = Session().get_credentials()
        AWS4Auth.__init__(self, access_id=kwargs.pop("access_id", "_"), secret_key=kwargs.pop("secret_key", "_"), region=region, service=service, **kwargs)

    def auth_flow(self, request):
        self.refresh_credentials()
        return super().auth_flow(request)

    def refresh_credentials(self):
        credentials = self.refreshable_credentials.get_frozen_credentials()
        self.access_id = credentials.access_key
        self.secret_key = credentials.secret_key
        self.security_token = credentials.token


aws = AWS4BotoAuth(region="eu-west-1")
with httpx.Client() as client:
    client.get('http://s3-eu-west-1.amazonaws.com', auth=aws)
```

## API key in header

You can send an API key inside the header of your request using `httpx_auth.HeaderApiKey`.

```python
import httpx
from httpx_auth import HeaderApiKey

with httpx.Client() as client:
    client.get('https://www.example.com', auth=HeaderApiKey('my_api_key'))
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `api_key`               | The API key that will be sent. | Mandatory |               |
| `header_name`           | Name of the header field.      | Optional  | "X-API-Key"   |

## API key in query

You can send an API key inside the query parameters of your request using `httpx_auth.QueryApiKey`.

```python
import httpx
from httpx_auth import QueryApiKey

with httpx.Client() as client:
    client.get('https://www.example.com', auth=QueryApiKey('my_api_key'))
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `api_key`               | The API key that will be sent. | Mandatory |               |
| `query_parameter_name`  | Name of the query parameter.   | Optional  | "api_key"     |

## Basic

You can use basic authentication using `httpx_auth.Basic`.

The only advantage of using this class instead of `httpx` native support of basic authentication, is to be able to use it in [multiple authentication](#multiple-authentication-at-once).

```python
import httpx
from httpx_auth import Basic

with httpx.Client() as client:
    client.get('https://www.example.com', auth=Basic('username', 'password'))
```

### Parameters

| Name                    | Description                    | Mandatory | Default value |
|:------------------------|:-------------------------------|:----------|:--------------|
| `username`              | User name.                     | Mandatory |               |
| `password`              | User password.                 | Mandatory |               |

## Multiple authentication at once

You can also use a combination of authentication using `+`or `&`  as in the following sample:

```python
import httpx
from httpx_auth import HeaderApiKey, OAuth2Implicit

api_key = HeaderApiKey('my_api_key')
oauth2 = OAuth2Implicit('https://www.example.com')
with httpx.Client() as client:
    client.get('https://www.example.com', auth=api_key + oauth2)
```

This is supported on every authentication class exposed by `httpx_auth`, but you can also enable it on your own authentication classes by using `httpx_auth.SupportMultiAuth` as in the following sample:

```python
from httpx_auth import SupportMultiAuth
# TODO Import your own auth here
from my_package import MyAuth

class MyMultiAuth(MyAuth, SupportMultiAuth):
    pass
```


## Available pytest fixtures

Testing the code using `httpx_auth` authentication classes can be achieved using provided [`pytest`][6] fixtures.

### token_cache_mock

```python
from httpx_auth.testing import token_cache_mock, token_mock

def test_something(token_cache_mock):
    # perform code using authentication
    pass
```

Use this fixture to mock authentication success for any of the following classes:
 * `OAuth2AuthorizationCodePKCE`
 * `OktaAuthorizationCodePKCE`
 * `OAuth2Implicit`
 * `OktaImplicit`
 * `OktaImplicitIdToken`
 * `AzureActiveDirectoryImplicit`
 * `AzureActiveDirectoryImplicitIdToken`
 * `OAuth2AuthorizationCode`
 * `OktaAuthorizationCode`
 * `WakaTimeAuthorizationCode`
 * `OAuth2ClientCredentials`
 * `OktaClientCredentials`
 * `OAuth2ResourceOwnerPasswordCredentials`
 * `OktaResourceOwnerPasswordCredentials`

By default, an access token with value `2YotnFZFEjr1zCsicMWpAA` is generated.

You can however return your custom token by providing your own `token_mock` fixture as in the following sample:

```python
import pytest

from httpx_auth.testing import token_cache_mock


@pytest.fixture
def token_mock() -> str:
    return "MyCustomTokenValue"


def test_something(token_cache_mock):
    # perform code using authentication
    pass
```

You can even return a more complex token by using the `create_token` function.

Note that [`pyjwt`](https://pypi.org/project/PyJWT/) is a required dependency in this case as it is used to generate the token returned by the authentication.

```python
import pytest
from httpx_auth.testing import token_cache_mock, create_token


@pytest.fixture
def token_mock() -> str:
    expiry = None  # TODO Compute your expiry
    return create_token(expiry)


def test_something(token_cache_mock):
    # perform code using authentication
    pass
```

### Advanced testing

#### token_cache

This [`pytest`][6] fixture will return the token cache and ensure it is reset at the end of the test case.

```python
from httpx_auth.testing import token_cache

def test_something(token_cache):
    # perform code using authentication
    pass
```

#### browser_mock

This [`pytest`][6] fixture will allow to mock the behavior of a web browser.

With this [`pytest`][6] fixture you will be allowed to fine tune your authentication related failures handling.

[`pyjwt`](https://pypi.org/project/PyJWT/) is a required dependency if you use `create_token` helper function.

```python
import datetime

from httpx_auth.testing import browser_mock, BrowserMock, create_token

def test_something(browser_mock: BrowserMock):
    token_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    token = create_token(token_expiry)
    tab = browser_mock.add_response(
        opened_url="http://url_opened_by_browser?state=1234",
        reply_url=f"http://localhost:5000#access_token={token}&state=1234",
    )

    # perform code using authentication

    tab.assert_success()
```

[1]: https://pypi.python.org/pypi/httpx "httpx module"
[2]: https://www.python-httpx.org/advanced/#customizing-authentication "authentication parameter on httpx module"
[3]: https://openid.net/specs/openid-connect-core-1_0.html#IDToken "OpenID ID Token specifications"
[4]: https://docs.python.org/3/library/webbrowser.html#webbrowser.open "Python webbrowser module"
[5]: https://github.com/python/cpython/blob/main/Lib/webbrowser.py "Python webbrowser module code"
[6]: https://docs.pytest.org/en/latest/ "pytest module"

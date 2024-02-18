class BrowserAuth:
    def __init__(self, kwargs):
        """
        :param redirect_uri_domain: FQDN to use in the redirect_uri when localhost (default) is not allowed.
        :param redirect_uri_endpoint: Custom endpoint that will be used as redirect_uri the following way:
        http://<redirect_uri_domain>:<redirect_uri_port>/<redirect_uri_endpoint>. Default value is to redirect on / (root).
        :param redirect_uri_port: The port on which the server listening for the OAuth 2 code will be started.
        Listen on port 5000 by default.
        :param timeout: Maximum amount of seconds to wait for a code or a token to be received once requested.
        Wait for 1 minute (60 seconds) by default.
        """
        redirect_uri_domain = kwargs.pop("redirect_uri_domain", None) or "localhost"
        redirect_uri_endpoint = kwargs.pop("redirect_uri_endpoint", None) or ""
        self.redirect_uri_port = int(kwargs.pop("redirect_uri_port", None) or 5000)
        self.redirect_uri = f"http://{redirect_uri_domain}:{self.redirect_uri_port}/{redirect_uri_endpoint}"

        # Time is expressed in seconds
        self.timeout = float(kwargs.pop("timeout", None) or 60)


class DisplaySettings:
    _default_template = """<!DOCTYPE html>
<html lang="en">
    <head>
        <title>{title}</title>
        <style>
body {{
    border: none;
    box-sizing: border-box;
    display: block;
    font-family: "Segoe UI";
    font-weight: 500;
    line-height: 1.5;
    padding: 50px 0 76px 0;
    text-align: center;
}}

.content {{
    padding: 30px 0 50px 0;
}}

h1 {{
    color: {color};
    font-size: 2.4rem;
    margin: 1.7rem auto .5rem auto;
}}

p {{
    color: #2f374f;
    font-size: 1.2rem;
    margin: .75rem 0 0 0;
}}

.btn {{
    display: inline-block;
    color: {color} !important;
    text-decoration: none;
    background-color: {background_color};
    padding: 14px 24px;
    border-radius: 8px;
    font-size: 1em;
    font-weight: 400;
    margin: 50px 0 0 0;
}}

.btn:hover {{
    color: {background_color} !important;
    background-color: {color};
}}

@keyframes zoomText {{
  from {{
    opacity: 0;
    transform: scale3d(0.9, 0.9, 0.9);
  }}
  50% {{
    opacity: 1;
  }}
}}

.content h1 {{
    animation-duration: .6s;
    animation-fill-mode: both;
    animation-name: zoomText;
    animation-delay: .2s;
}}
        </style>
    </head>
    <body onload="window.open('', '_self', ''); window.setTimeout(close, {display_time})">
        <div class="content">
            <h1>{title}</h1>
            <p>{information}</p>
        </div>
        <div class="more">
            <a href="https://colin-b.github.io/httpx_auth/" class="btn" target="_blank" rel="noreferrer noopener" role="button">Documentation</a>
            <a href="https://github.com/Colin-b/httpx_auth/blob/develop/CHANGELOG.md" class="btn" target="_blank" rel="noreferrer noopener" role="button">Latest changes</a>
        </div>
    </body>
</html>"""
    _default_success = (
        _default_template.replace("{title}", "Authentication success")
        .replace("{color}", "#32cd32")
        .replace("{background_color}", "#f0fff0")
        .replace("{information}", "You can close this tab")
    )
    _default_failure = (
        _default_template.replace("{title}", "Authentication failed")
        .replace("{color}", "#dc143c")
        .replace("{background_color}", "#fffafa")
    )

    def __init__(
        self,
        *,
        success_display_time: int = 1,
        success_html: str = None,
        failure_display_time: int = 10_000,
        failure_html: str = None,
    ):
        """
        :param success_display_time: In case a code/token is successfully received,
        this is the maximum amount of milliseconds the success page will be displayed in your browser.
        Display the page for 1 millisecond by default.
        :param success_html: In case a code or token is successfully received,
        this is the success page that will be displayed in your browser.
        `{display_time}` is expected in this content.
        :param failure_display_time: In case received code/token is not valid,
        this is the maximum amount of milliseconds the failure page will be displayed in your browser.
        Display the page for 10 seconds by default.
        :param failure_html: In case received code or token is not valid,
        this is the failure page that will be displayed in your browser.
        `{information}` and `{display_time}` are expected in this content.
        """
        # Time is expressed in milliseconds
        self.success_display_time = success_display_time
        self.success_html = success_html or self._default_success

        # Time is expressed in milliseconds
        self.failure_display_time = failure_display_time
        self.failure_html = failure_html or self._default_failure

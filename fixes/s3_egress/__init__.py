"""S3 fix: egress allow-lists, outbound DLP, output sanitisation. See README.md.

    cfg.hardening = hardening(web_netlocs=("mock-web:8080",))
"""


def hardening(web_netlocs=("mock-web:8080",), email_domains=("acme.example",)) -> dict:
    return {
        "fetch_allowlist": set(web_netlocs),  # fetch_url may only reach these host:port pairs
        "email_domains": set(email_domains),  # send_email may only go to these domains
        "dlp": True,  # block secret-looking data in URLs and emails
        "sanitize_output": True,  # strip images/non-allow-listed links/HTML, redact secrets
        "link_allowlist": set(web_netlocs),
    }

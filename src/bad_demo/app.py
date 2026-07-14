"""Flask entry point wiring all vulnerabilities together.

OWASP Top 10 mapping:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection (SQL, XSS, Command, LDAP)
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery
"""

from flask import Flask, request

from bad_demo.auth import authenticate, create_session_token, legacy_login, verify_session_token, weak_hash_token
from bad_demo.config import DEBUG, SECRET_KEY
from bad_demo.crypto import encrypt_xor, generate_pin, hash_password_md5
from bad_demo.db import delete_user_unsafe, find_user_unsafe, search_users_unsafe
from bad_demo.deserialization import load_config, load_user_object
from bad_demo.exec_utils import run_lookup, run_ping
from bad_demo.http_utils import fetch_metadata, fetch_url
from bad_demo.ldap_utils import ldap_login
from bad_demo.logging_utils import log_error, log_login
from bad_demo.templates import render_comment, render_search_results

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.route("/")
def index():
    return "<h1>Bad Demo</h1><p>Intentionally vulnerable app for SAST testing.</p>"


@app.route("/login", methods=["POST"])
def login():
    """A07 + A03: Broken auth with SQL injection."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # A09: log credentials
    log_login(username, password, False)

    # A07: hardcoded backdoor
    user = legacy_login(username, password)
    if user:
        token = create_session_token(user)
        return f"Welcome admin. Token: {token}"

    # A03/A07: injection through authentication
    if authenticate(username, password):
        token = create_session_token({"username": username})
        return f"Logged in. Token: {token}"

    log_error("Failed login for " + username)
    return "Invalid credentials", 401


@app.route("/search")
def search():
    """A03: Reflected XSS and SQL injection."""
    q = request.args.get("q", "")
    # Taint crosses from request -> db.search_users_unsafe -> SQL sink
    results = search_users_unsafe(q)
    # Taint crosses from q -> templates.render_search_results -> HTML sink
    return render_search_results(q, results)


@app.route("/comment", methods=["POST"])
def comment():
    """A03: Stored/reflected XSS."""
    name = request.form.get("name", "")
    body = request.form.get("body", "")
    return render_comment(name, body)


@app.route("/ping", methods=["POST"])
def ping():
    """A03: OS command injection."""
    host = request.form.get("host", "")
    # Cross-file taint to os.system
    run_ping(host)
    return f"Pinged {host}"


@app.route("/lookup", methods=["POST"])
def lookup():
    """A03: OS command injection via subprocess."""
    host = request.form.get("host", "")
    run_lookup(host)
    return f"Lookup complete for {host}"


@app.route("/ldap", methods=["POST"])
def ldap_auth():
    """A03: LDAP injection."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    result = ldap_login(username, password)
    return str(result)


@app.route("/fetch")
def fetch():
    """A10: SSRF."""
    url = request.args.get("url", "")
    # Cross-file taint to requests.get
    content = fetch_url(url)
    return f"<pre>{content}</pre>"


@app.route("/metadata")
def metadata():
    """A10: SSRF to cloud metadata."""
    service = request.args.get("service", "")
    return fetch_metadata(service)


@app.route("/load", methods=["POST"])
def load():
    """A08: Insecure deserialization."""
    data = request.get_data()
    obj = load_user_object(data)
    return str(obj)


@app.route("/config/load", methods=["POST"])
def load_yaml():
    """A08: Unsafe YAML load."""
    text = request.get_data(as_text=True)
    cfg = load_config(text)
    return str(cfg)


@app.route("/admin")
def admin():
    """A01: Broken access control."""
    token = request.args.get("token", "")
    session = verify_session_token(token)
    # A01: Missing authorization check beyond token presence
    if session:
        return "Admin panel"
    return "Forbidden", 403


@app.route("/admin/delete")
def admin_delete():
    """A01: Broken access control + A03 SQL injection."""
    token = request.args.get("token", "")
    session = verify_session_token(token)
    if not session:
        return "Forbidden", 403

    user_id = request.args.get("id", "")
    # A01: No role check; any valid token can delete
    # A03: SQL injection via delete_user_unsafe
    delete_user_unsafe(user_id)
    return "User deleted"


@app.route("/register", methods=["POST"])
def register():
    """A02/A07: Weak crypto + insecure design."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # A02: MD5 password hash
    hashed = hash_password_md5(password)
    pin = generate_pin()
    # A04: Insecure design - storing PIN alongside hash
    return f"User {username} registered with hash {hashed} and PIN {pin}"


@app.route("/encrypt", methods=["POST"])
def encrypt():
    """A02: Broken home-grown crypto."""
    text = request.form.get("text", "")
    return encrypt_xor(text)


@app.route("/debug")
def debug_info():
    """A05: Information disclosure via debug mode."""
    if DEBUG:
        return {"config": {"debug": DEBUG, "secret_key": SECRET_KEY}}
    return "OK"


def main():
    app.run(host="0.0.0.0", port=5000, debug=DEBUG)


if __name__ == "__main__":
    main()

"""LDAP injection sinks (A03:2021 - Injection)."""

from ldap3 import Connection, Server


def ldap_login(username, password):
    """Authenticate against LDAP using a concatenated filter.

    Taint source -> username/password -> LDAP filter sink.
    """
    server = Server("localhost", port=389)
    conn = Connection(server, user=f"cn={username},dc=example,dc=com", password=password)
    # A03:2021 - LDAP Injection via unsanitized filter
    search_filter = f"(uid={username})"
    conn.bind()
    conn.search(
        "dc=example,dc=com",
        search_filter,
        search_scope="SUBTREE",
    )
    return conn.entries

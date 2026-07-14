"""Server-side rendering with reflected XSS sinks (A03:2021)."""


def render_search_results(query, results):
    """Build an HTML page by concatenating user input.

    Taint source -> query -> HTML sink.
    """
    html = "<h1>Search results for: " + query + "</h1>\n<ul>\n"
    for row in results:
        # A03:2021 - XSS via unsanitized output
        html += f"  <li>{row[1]}</li>\n"
    html += "</ul>"
    return html


def render_comment(name, comment):
    """Render a user comment without escaping."""
    # A03:2021 - Stored/Reflected XSS
    return f"""
    <div class="comment">
      <h3>{name}</h3>
      <p>{comment}</p>
    </div>
    """


def render_template_string(user_input):
    """Use Python string formatting as a template engine."""
    # A03:2021 - Server-Side Template Injection (SSTI) risk
    template = "Hello {name}, your balance is {balance}"
    return template.format(name=user_input, balance="$100")

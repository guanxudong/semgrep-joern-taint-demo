"""Email / notice rendering for recon results."""
from jinja2 import Environment


def render_result_email(account, rows):
    lines = [f"<h2>Recon result for {account}</h2>", "<table>"]
    for row in rows:
        lines.append(f"<tr><td>{row['symbol']}</td><td>{row['diff']}</td></tr>")
    lines.append("</table>")
    return "\n".join(lines)


def render_notice(template, payload):
    env = Environment()
    return env.from_string(template).render(**payload)

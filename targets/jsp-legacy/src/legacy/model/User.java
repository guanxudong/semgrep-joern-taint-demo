package legacy.model;

/** User bean for the reflection-based profile update page. */
public class User {
    public String username = "";
    public String email = "";
    // VULN: jsp-priv-esc-01 (priv-esc, cwe-269) - role is a plain public field, settable from request params
    public String role = "user";
}

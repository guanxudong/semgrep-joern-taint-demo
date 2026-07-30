package legacy.service;

import java.sql.ResultSet;

import legacy.data.UserRepository;

/** User lookup logic; holds tainted input in an instance field between calls. */
public class UserService {

    private final UserRepository repo = new UserRepository();

    /** Tainted value staged by the page (taint via field). */
    private String pendingName;

    public void stageName(String name) {
        this.pendingName = name;
    }

    // VULN: jsp-sqli-02 (sqli, cwe-89) - reads the staged field and reaches the sink (deep chain end)
    public ResultSet findStaged() throws Exception {
        String sql = "SELECT id, username, email FROM users WHERE username = '" + this.pendingName + "'";
        return repo.queryUnsafe(sql);
    }

    // VULN: jsp-idor-01 (idor, cwe-639) - fetches any user by id, no ownership check
    public ResultSet findById(String id) throws Exception {
        String sql = "SELECT id, username, email, role FROM users WHERE id = " + id;
        return repo.queryUnsafe(sql);
    }

    // SAFE: jsp-safe-02 (mimics idor) - parameterized lookup after ownership check in the page
    public ResultSet findByIdSafe(String id) throws Exception {
        return repo.querySafe("SELECT id, username, email, role FROM users WHERE id = ?", id);
    }
}

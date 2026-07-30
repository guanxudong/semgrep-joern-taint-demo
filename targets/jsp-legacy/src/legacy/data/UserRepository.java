package legacy.data;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

import legacy.config.AppConfig;

/** Raw JDBC data access. The unsafe methods are the SQLi sinks. */
public class UserRepository {

    private Connection connect() throws Exception {
        return DriverManager.getConnection(AppConfig.DB_URL, AppConfig.DB_USER, AppConfig.DB_PASSWORD);
    }

    // VULN: jsp-sqli-01 (sqli, cwe-89) - sink: executes SQL built by callers via concatenation
    // VULN: jsp-sqli-02 (sqli, cwe-89) - same sink, reached through UserService
    public ResultSet queryUnsafe(String sql) throws Exception {
        Statement stmt = connect().createStatement();
        return stmt.executeQuery(sql);
    }

    // VULN: jsp-broken-access-control-01 (broken-access-control, cwe-862) - unguarded delete
    public void executeUnsafe(String sql) throws Exception {
        Statement stmt = connect().createStatement();
        stmt.executeUpdate(sql);
    }

    // SAFE: jsp-safe-01 (mimics sqli) - parameterized query
    public ResultSet querySafe(String sql, String arg) throws Exception {
        PreparedStatement ps = connect().prepareStatement(sql);
        ps.setString(1, arg);
        return ps.executeQuery();
    }
}

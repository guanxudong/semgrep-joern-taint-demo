package MyApp::DB;
# Raw DBI data-access helpers.
use strict;
use warnings;
use DBI;
use MyApp::Config;

sub connect_db {
    my $dsn = 'DBI:SQLite:dbname=' . MyApp::Config->DB_PATH;
    return DBI->connect($dsn, MyApp::Config->DB_USER, MyApp::Config->DB_PASSWORD,
        { RaiseError => 1, PrintError => 0 });
}

# Execute a raw SQL string built by the caller.
sub query {
    my ($class, $sql) = @_;
    my $dbh  = $class->connect_db;
    my $rows = $dbh->selectall_arrayref($sql);
    $dbh->disconnect;
    return $rows;
}

# Parameterized query helper.
sub query_prepared {
    my ($class, $sql, @bind) = @_;
    my $dbh  = $class->connect_db;
    my $sth  = $dbh->prepare($sql);
    $sth->execute(@bind);
    my $rows = $sth->fetchall_arrayref;
    $dbh->disconnect;
    return $rows;
}

sub execute {
    my ($class, $sql) = @_;
    my $dbh = $class->connect_db;
    $dbh->do($sql);
    $dbh->disconnect;
}

1;

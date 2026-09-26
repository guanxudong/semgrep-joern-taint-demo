package MyApp::DB;
use strict;
use warnings;
use DBI;

use MyApp::Config;

sub connect_db {
    return DBI->connect('dbi:SQLite:dbname=' . MyApp::Config::DB_PATH, '', '');
}

sub query {
    my ($sql) = @_;
    my $dbh  = connect_db();
    my $rows = $dbh->selectall_arrayref($sql, { Slice => {} });
    $dbh->disconnect;
    return $rows;
}

sub query_prepared {
    my ($sql, @params) = @_;
    my $dbh  = connect_db();
    my $rows = $dbh->selectall_arrayref($sql, { Slice => {} }, @params);
    $dbh->disconnect;
    return $rows;
}

sub execute {
    my ($sql) = @_;
    my $dbh = connect_db();
    $dbh->do($sql);
    $dbh->disconnect;
}

1;

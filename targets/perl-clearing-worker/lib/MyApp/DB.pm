package MyApp::DB;
use strict;
use warnings;

sub select_rows {
    my ($sql) = @_;
    return [];
}

sub select_rows_safe {
    my ($sql, @bind) = @_;
    return [];
}

sub do_sql {
    my ($sql) = @_;
    return 1;
}

1;

#!/usr/bin/perl
# Admin: list all user accounts.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../lib";
use CGI;
use MyApp::DB;

sub run {
    my $q    = CGI->new;
    my $rows = MyApp::DB->query('SELECT id, username, email, role FROM users');
    print $q->header('text/html');
    print "<ul>\n";
    for my $row (@$rows) {
        print "<li>$row->[0]: $row->[1] ($row->[2]) role=$row->[3]</li>\n";
    }
    print "</ul>\n";
}

run();
